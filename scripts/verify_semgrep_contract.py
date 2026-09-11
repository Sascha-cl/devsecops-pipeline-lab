"""Exercise the pinned real Semgrep image against tiny, synthetic fixtures.

This is an integration test, not a security scan of a real application.
No internet targets or credentials are involved. Run after a scanner update.
"""

import json
import uuid
from pathlib import Path

from scan import ROOT, Session, container_inputs, load_lock, report_directory
from validate_reports import require, validate
import subprocess


def main():
    lock = load_lock(ROOT)
    output = report_directory(ROOT / "reports/semgrep" / ("contract-" + uuid.uuid4().hex[:12]))
    session = Session(lock, output)
    summary = {"status": "failed", "image": lock["images"]["semgrep"], "cases": []}
    try:
        with container_inputs("devsecops-contract-") as temporary:
            source = Path(temporary)
            (source / "rule.yml").write_text(
                "rules:\n  - id: lab-eval\n    languages: [javascript]\n"
                "    severity: WARNING\n    message: Synthetic eval fixture\n"
                "    pattern: eval($X)\n", encoding="utf-8")
            for case, code in (("finding", "eval(userInput);\n"), ("clean", "String(userInput);\n")):
                (source / "app.js").write_text(code, encoding="utf-8")
                result = report_directory(output / case)
                session.docker(lock["images"]["semgrep"],
                    ["semgrep", "scan", "--strict", "--metrics", "off", "--disable-version-check",
                     "--config", "/src/rule.yml", "--json", "--output", "/out/semgrep.json",
                     "--sarif-output", "/out/semgrep.sarif", "/src/app.js"],
                    session.mount(source, "/src", True) + session.mount(result, "/out"))
                checked = validate("semgrep", result)
                require(checked["findings"] == (1 if case == "finding" else 0), "Fixture result changed")
                summary["cases"].append({"case": case, "exit_code": 0, **checked})
            (source / "broken.yml").write_text("rules: [\n", encoding="utf-8")
            try:
                session.docker(lock["images"]["semgrep"],
                    ["semgrep", "scan", "--strict", "--metrics", "off", "--disable-version-check",
                     "--config", "/src/broken.yml", "/src/app.js"],
                    session.mount(source, "/src", True))
            except subprocess.CalledProcessError as error:
                require(error.returncode != 0, "Invalid config unexpectedly succeeded")
                summary["cases"].append({"case": "invalid-config", "exit_code": error.returncode,
                                         "runner_rejected": True})
            else:
                raise ValueError("Invalid config unexpectedly succeeded")
        summary["status"] = "success"
        print(json.dumps(summary, indent=2))
    finally:
        session.cleanup()
        (output / "contract.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
