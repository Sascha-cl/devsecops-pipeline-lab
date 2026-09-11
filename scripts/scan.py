"""Same fail-closed scan runner locally and in GitHub Actions.

Python standard library only. No shell command strings or Docker socket mounts.
Per-run resource names prevent interference with unrelated containers and volumes.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from validate_reports import require, validate

ROOT = Path(__file__).resolve().parents[1]


def run(command, timeout=600, capture=False):
    print("+ " + shlex.join(str(arg) for arg in command), flush=True)
    return subprocess.run(command, check=True, timeout=timeout, text=True,
                          encoding="utf-8", errors="replace", stdout=subprocess.PIPE if capture else None)


def load_lock(root):
    lock = json.loads((root / "config/scan-lock.json").read_text(encoding="utf-8"))
    for image in [lock["target"]["image"], *lock["images"].values()]:
        require(re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image), "Images must use immutable digests")
    for item in (lock["target"], lock["semgrep_rules"]):
        require(re.fullmatch(r"[a-f0-9]{40}", item["revision"]), "Source/rules need full commit SHAs")
    require(lock["platform"] == "linux/amd64", "This lab is verified on linux/amd64")
    return lock


class Session:
    def __init__(self, lock, output):
        self.lock, self.output = lock, output
        self.prefix = "devsecops-lab-" + uuid.uuid4().hex[:12]
        self.containers, self.networks, self.volumes = [], [], []

    def docker(self, image, arguments, options=(), timeout=600, capture=False):
        name = self.prefix + "-" + str(len(self.containers))
        self.containers.append(name)
        return run(["docker", "run", "--rm", "--name", name, "--platform", self.lock["platform"],
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--group-add", str(os.getgid() if hasattr(os, "getgid") else 0),
                    *options, image, *arguments], timeout=timeout, capture=capture)

    def mount(self, path, destination, readonly=False):
        return ["--mount", f"type=bind,src={Path(path).resolve()},dst={destination}" + (",readonly" if readonly else "")]

    def cleanup(self):
        for kind, names in (("container", self.containers), ("network", self.networks), ("volume", self.volumes)):
            for name in reversed(names):
                command = ["docker", kind, "rm", *(["-f"] if kind == "container" else []), name]
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    if result.returncode and "No such" not in result.stderr:
                        print(f"Cleanup warning for {name}: {result.stderr.strip()}", file=sys.stderr)
                except (OSError, subprocess.TimeoutExpired) as error:
                    print(f"Cleanup warning for {name}: {error}", file=sys.stderr)


def checkout(repository, revision, destination):
    run(["git", "init", "--quiet", str(destination)])
    run(["git", "-C", str(destination), "remote", "add", "origin", repository])
    run(["git", "-C", str(destination), "fetch", "--quiet", "--depth", "1", "origin", revision])
    run(["git", "-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    actual = run(["git", "-C", str(destination), "rev-parse", "HEAD"], capture=True).stdout.strip()
    require(actual == revision, "Checked-out commit differs from lock")


def verify_target(session):
    target = session.lock["target"]
    run(["docker", "pull", "--platform", session.lock["platform"], target["image"]])
    details = json.loads(run(["docker", "image", "inspect", target["image"]], capture=True).stdout)[0]
    revision = details.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision", "")
    require(re.fullmatch(r"[a-f0-9]{7,40}", revision) and target["revision"].startswith(revision),
            "Image revision label does not match the pinned source commit")
    require(details.get("Architecture") == "amd64", "Unexpected image architecture")
    (session.output / "target.json").write_text(json.dumps({"image": target["image"], "revision_label": revision,
        "source_revision": target["revision"], "image_id": details["Id"]}, indent=2) + "\n", encoding="utf-8")


def gitleaks(session, root):
    # dir additionally covers uncommitted files during local development.
    for mode, filename in (("git", "gitleaks-history.json"), ("dir", "gitleaks-worktree.json")):
        session.docker(session.lock["images"]["gitleaks"],
            [mode, "/repo", *(["--log-opts=--all"] if mode == "git" else []), "--report-format", "json", "--report-path", "/out/" + filename,
             "--redact", "--exit-code", "1"],
            session.mount(root, "/repo", True) + session.mount(session.output, "/out"))


def semgrep(session, root):
    verify_target(session)
    with tempfile.TemporaryDirectory(prefix="devsecops-inputs-") as temporary:
        source, rules = Path(temporary) / "source", Path(temporary) / "rules"
        for item, destination in ((session.lock["target"], source), (session.lock["semgrep_rules"], rules)):
            checkout(item["repository"], item["revision"], destination)
        arguments = ["semgrep", "scan", "--strict", "--metrics", "off", "--disable-version-check",
                     "--no-git-ignore", "--json", "--output", "/out/semgrep.json", "--sarif-output", "/out/semgrep.sarif"]
        for directory in session.lock["semgrep_rules"]["directories"]:
            arguments += ["--config", "/rules/" + directory]
        for excluded in session.lock["semgrep_excludes"]:
            arguments += ["--exclude", excluded]
        # No --error: findings are expected. Strict mode and checked exit status
        # still reject invalid rules, parse errors and scanner failures.
        session.docker(session.lock["images"]["semgrep"], arguments + ["."],
            ["--workdir", "/src"] + session.mount(source, "/src", True) + session.mount(rules, "/rules", True)
            + session.mount(session.output, "/out"), timeout=900)


def trivy(session, root):
    verify_target(session)
    cache = session.prefix + "-cache"
    session.volumes.append(cache)
    options = ["--mount", f"type=volume,src={cache},dst=/root/.cache"] + session.mount(session.output, "/out")
    session.docker(session.lock["images"]["trivy"],
        ["image", "--platform", session.lock["platform"], "--image-src", "remote", "--timeout", "10m",
         "--format", "json", "--output", "/out/trivy.json", "--scanners", "vuln", "--exit-code", "0",
         session.lock["target"]["image"]], options, timeout=900)
    # Same cache as the scan; capture database metadata, not a second scan.
    db = session.docker(session.lock["images"]["trivy"], ["version", "--format", "json"], options, capture=True)
    (session.output / "trivy-db.json").write_text(db.stdout, encoding="utf-8")


def zap(session, root):
    verify_target(session)
    network = session.prefix + "-net"
    session.networks.append(network)
    run(["docker", "network", "create", network])
    # No host port, privileged mode or Docker socket for the vulnerable target.
    session.docker(session.lock["target"]["image"], [],
                   ["--detach", "--network", network, "--network-alias", "juice-shop"])
    session.docker(session.lock["images"]["curl"],
        ["--fail", "--silent", "--show-error", "--output", "/dev/null", "--connect-timeout", "2", "--max-time", "3",
         "--retry", "30", "--retry-delay", "2", "--retry-all-errors", "--retry-max-time", "150", "http://juice-shop:3000"],
        ["--network", network], timeout=180)
    session.docker(session.lock["images"]["zap"],
        ["zap-baseline.py", "-t", "http://juice-shop:3000", "-J", "zap.json", "-r", "zap.html", "-m", "2", "-T", "5", "-I"],
        ["--network", network] + session.mount(session.output, "/zap/wrk"), timeout=600)


SCANNERS = {"gitleaks": gitleaks, "semgrep": semgrep, "trivy": trivy, "zap": zap}


def execute(tool, root=ROOT):
    lock = load_lock(root)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = root / "reports" / tool / stamp
    output.mkdir(parents=True, exist_ok=False)  # Never reuse stale success reports.
    output.chmod(0o770)  # Supplemental host group gives non-root ZAP write access on Linux.
    session = Session(lock, output)
    metadata = {"tool": tool, "started_at": datetime.now(timezone.utc).isoformat(), "lock": lock, "status": "failed"}
    metadata["implementation_sha256"] = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("scripts/scan.py", "scripts/validate_reports.py", "config/scan-lock.json")
        if (root / name).is_file()
    }
    try:
        metadata["repository_commit"] = run(["git", "-C", str(root), "rev-parse", "HEAD"], capture=True).stdout.strip()
        metadata["worktree_dirty"] = bool(run(["git", "--no-optional-locks", "-C", str(root), "status", "--porcelain"], capture=True).stdout.strip())
        SCANNERS[tool](session, root)
        metadata["result"] = validate(tool, output, expected_target=lock["target"]["image"])
        metadata["status"] = "success"
        summary = f"### {tool}\n\nScan completed; expected lab findings are not a release approval.\n\n"
        summary += json.dumps(metadata["result"], indent=2) + "\n"
        (output / "summary.md").write_text(summary, encoding="utf-8")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
                handle.write(summary)
        print(summary)
        return output
    except Exception as error:
        metadata["status"] = "failed"
        metadata["error"] = str(error)
        raise
    finally:
        session.cleanup()
        metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        (output / "run.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print(f"Reports: {output}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", choices=SCANNERS)
    arguments = parser.parse_args()
    try:
        execute(arguments.scanner)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"SCAN FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
