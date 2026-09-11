"""Regression tests use synthetic reports; no live targets, Docker or secrets needed."""

import contextlib
import copy
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan
from validate_reports import validate


def semgrep_reports(folder, count=1):
    data = {"errors": [], "paths": {"scanned": ["routes/example.ts"]},
            "results": [{"check_id": "example-rule"} for _ in range(count)]}
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"rules": [{"id": "example-rule"}]}},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
        "results": [{"ruleId": "example-rule"} for _ in range(count)]
    }]}
    for name, content in (("semgrep.json", data), ("semgrep.sarif", sarif)):
        (folder / name).write_text(json.dumps(content), encoding="utf-8")
    return data, sarif


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def write(self, name, data):
        (self.folder / name).write_text(json.dumps(data), encoding="utf-8")

    def test_expected_semgrep_findings_are_allowed(self):
        semgrep_reports(self.folder, 3)
        self.assertEqual(validate("semgrep", self.folder)["findings"], 3)

    def test_zero_findings_with_actual_coverage_are_allowed(self):
        semgrep_reports(self.folder, 0)
        self.assertEqual(validate("semgrep", self.folder)["findings"], 0)

    def test_missing_reports_fail_for_every_scanner(self):
        for tool in scan.SCANNERS:
            with self.subTest(tool=tool), self.assertRaises(ValueError):
                validate(tool, self.folder)

    def test_empty_and_malformed_json_fail(self):
        for content in ("", "{broken"):
            (self.folder / "semgrep.json").write_text(content, encoding="utf-8")
            with self.subTest(content=content), self.assertRaises(ValueError):
                validate("semgrep", self.folder)

    def test_partial_semgrep_scan_fails_even_with_findings(self):
        data, _ = semgrep_reports(self.folder)
        data["errors"] = [{"type": "Syntax error"}]
        self.write("semgrep.json", data)
        with self.assertRaisesRegex(ValueError, "technical errors"):
            validate("semgrep", self.folder)

    def test_zero_scanned_files_fail(self):
        data, _ = semgrep_reports(self.folder)
        data["paths"]["scanned"] = []
        self.write("semgrep.json", data)
        with self.assertRaisesRegex(ValueError, "zero files"):
            validate("semgrep", self.folder)

    def test_missing_sarif_fails(self):
        semgrep_reports(self.folder)
        (self.folder / "semgrep.sarif").unlink()
        with self.assertRaises(ValueError):
            validate("semgrep", self.folder)

    def test_sarif_failures_and_missing_rules_fail(self):
        _, good = semgrep_reports(self.folder)
        for fault in ("failed", "warning", "no-rules", "no-invocations", "no-runs"):
            sarif = copy.deepcopy(good)
            item = sarif["runs"][0]
            if fault == "failed":
                item["invocations"][0]["executionSuccessful"] = False
            elif fault == "warning":
                item["invocations"][0]["toolExecutionNotifications"] = [{"level": "warning"}]
            elif fault == "no-rules":
                item["tool"]["driver"]["rules"] = []
            elif fault == "no-invocations":
                item["invocations"] = []
            else:
                sarif["runs"] = []
            self.write("semgrep.sarif", sarif)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                validate("semgrep", self.folder)

    def test_conflicting_reports_fail(self):
        _, sarif = semgrep_reports(self.folder)
        sarif["runs"][0]["results"] = []
        self.write("semgrep.sarif", sarif)
        with self.assertRaisesRegex(ValueError, "disagree"):
            validate("semgrep", self.folder)

    def test_secrets_block_but_clean_history_and_worktree_pass(self):
        self.write("gitleaks-history.json", [])
        self.write("gitleaks-worktree.json", [])
        self.assertEqual(validate("gitleaks", self.folder)["findings"], 0)
        self.write("gitleaks-worktree.json", [{"RuleID": "synthetic-test", "Secret": "REDACTED"}])
        with self.assertRaisesRegex(ValueError, "Secret findings"):
            validate("gitleaks", self.folder)

    def test_trivy_critical_findings_are_allowed_but_db_metadata_required(self):
        self.write("trivy.json", {"Metadata": {"RepoDigests": ["example@sha256:synthetic"]},
            "Results": [{"Target": "Node.js", "Vulnerabilities": [{"Severity": "CRITICAL"}]}]})
        with self.assertRaises(ValueError):
            validate("trivy", self.folder)
        self.write("trivy-db.json", {"VulnerabilityDB": {"UpdatedAt": "2026-09-11T00:00:00Z"}})
        self.assertEqual(validate("trivy", self.folder)["severity"]["CRITICAL"], 1)
        with self.assertRaisesRegex(ValueError, "wrong image"):
            validate("trivy", self.folder, expected_target="different@sha256:digest")

    def test_trivy_without_targets_fails(self):
        self.write("trivy.json", {"Results": []})
        with self.assertRaises(ValueError):
            validate("trivy", self.folder)

    def test_zap_requires_correct_target_and_html(self):
        self.write("zap.json", {"site": [{"@name": "http://juice-shop:3000", "alerts": []}]})
        with self.assertRaisesRegex(ValueError, "HTML"):
            validate("zap", self.folder)
        (self.folder / "zap.html").write_text("<html>synthetic test</html>", encoding="utf-8")
        self.assertEqual(validate("zap", self.folder)["findings"], 0)
        self.write("zap.json", {"site": [{"@name": "http://wrong-target:3000", "alerts": []}]})
        with self.assertRaisesRegex(ValueError, "Wrong ZAP target"):
            validate("zap", self.folder)


class ExecutionTests(unittest.TestCase):
    def test_image_revision_and_platform_must_match_source(self):
        lock = scan.load_lock(scan.ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            session = scan.Session(lock, Path(temporary))
            for revision, architecture, valid in ((lock["target"]["revision"][:7], "amd64", True),
                                                  ("0000000", "amd64", False),
                                                  (lock["target"]["revision"][:7], "arm64", False)):
                details = [{"Config": {"Labels": {"org.opencontainers.image.revision": revision}},
                            "Architecture": architecture, "Id": "synthetic-image"}]
                result = subprocess.CompletedProcess([], 0, stdout=json.dumps(details))
                with patch.object(scan, "run", return_value=result):
                    if valid:
                        scan.verify_target(session)
                    else:
                        with self.assertRaises(ValueError):
                            scan.verify_target(session)

    def test_nonzero_process_exit_is_not_swallowed(self):
        with self.assertRaises(subprocess.CalledProcessError) as error:
            scan.run([sys.executable, "-c", "raise SystemExit(7)"])
        self.assertEqual(error.exception.returncode, 7)

    def test_process_timeout_is_not_swallowed(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            scan.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)

    def test_cli_reports_failure(self):
        with patch.object(sys, "argv", ["scan.py", "semgrep"]), \
             patch.object(scan, "execute", side_effect=ValueError("Missing report")), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scan.main(), 1)

    def test_execute_rejects_failed_scanner_and_stale_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config").mkdir()
            (root / "config/scan-lock.json").write_text(
                (scan.ROOT / "config/scan-lock.json").read_text(encoding="utf-8"), encoding="utf-8")
            old = root / "reports/semgrep/old"
            old.mkdir(parents=True)
            semgrep_reports(old)
            good_git = subprocess.CompletedProcess([], 0, stdout="synthetic-test-commit")
            for scenario in ("failed-command", "no-report", "good-report"):
                def worker(session, _root):
                    if scenario == "failed-command":
                        raise subprocess.CalledProcessError(2, ["synthetic-scanner"])
                    if scenario == "good-report":
                        semgrep_reports(session.output)
                with patch.dict(scan.SCANNERS, {"semgrep": worker}), \
                     patch.object(scan, "run", return_value=good_git):
                    if scenario == "good-report":
                        output = scan.execute("semgrep", root)
                        self.assertEqual(json.loads((output / "run.json").read_text())["status"], "success")
                    else:
                        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                            scan.execute("semgrep", root)
            statuses = [json.loads(p.read_text())["status"] for p in (root / "reports").rglob("run.json")]
            self.assertEqual(sorted(statuses), ["failed", "failed", "success"])

    @unittest.skipUnless(hasattr(os, "getgid"), "File modes only apply to POSIX hosts")
    def test_mounted_paths_stay_usable_for_restricted_containers(self):
        # --cap-drop ALL removes CAP_DAC_OVERRIDE, so even uid 0 obeys file modes.
        # A 0700 temp dir denies mounted reads, an umask-reduced 0750 output dir denies writes.
        previous = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as root:
                report = scan.report_directory(Path(root) / "reports/semgrep/run")
                self.assertEqual(stat.S_IMODE(report.stat().st_mode) & 0o070, 0o070)
                with self.assertRaises(FileExistsError):
                    scan.report_directory(report)
            with scan.container_inputs("devsecops-test-") as temporary:
                inputs = Path(temporary)
                (inputs / "rule.yml").write_text("rules: []\n", encoding="utf-8")
                self.assertEqual(stat.S_IMODE(inputs.stat().st_mode) & 0o050, 0o050)
                self.assertEqual(stat.S_IMODE((inputs / "rule.yml").stat().st_mode) & 0o040, 0o040)
            self.assertFalse(inputs.exists())
        finally:
            os.umask(previous)

    def test_pins_and_workflow_guardrails(self):
        lock = scan.load_lock(scan.ROOT)
        self.assertEqual(len(lock["target"]["revision"]), 40)
        workflow = (scan.ROOT / ".github/workflows/security-pipeline.yml").read_text(encoding="utf-8")
        self.assertNotIn("continue-on-error:", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("needs: [pipeline-tests, scan]", workflow)
        self.assertIn('test "$SCAN_RESULT" = success', workflow)

    def test_mutable_image_tag_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config").mkdir()
            lock = scan.load_lock(scan.ROOT)
            lock["images"]["semgrep"] = "semgrep/semgrep:latest"
            (root / "config/scan-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "immutable"):
                scan.load_lock(root)


if __name__ == "__main__":
    unittest.main()
