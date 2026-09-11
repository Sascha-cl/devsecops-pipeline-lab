"""Fail closed on missing/incomplete scans, not on expected Juice Shop findings."""

import json
from collections import Counter
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    path = Path(path)
    require(path.is_file() and path.stat().st_size > 0, f"Missing/empty report: {path.name}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate(tool, directory, expected_target=None):
    directory = Path(directory)
    if tool == "gitleaks":
        total = 0
        for name in ("gitleaks-history.json", "gitleaks-worktree.json"):
            findings = read_json(directory / name)
            require(isinstance(findings, list), "Invalid Gitleaks report")
            total += len(findings)
        require(total == 0, "Secret findings block this repository")
        return {"findings": total, "scope": "history + current files"}

    if tool == "semgrep":
        data = read_json(directory / "semgrep.json")
        require(isinstance(data, dict), "Invalid Semgrep JSON")
        require(isinstance(data.get("errors"), list) and not data["errors"],
                "Semgrep reported technical errors; scan coverage is incomplete")
        require(isinstance(data.get("results"), list), "Missing Semgrep results")
        scanned = data.get("paths", {}).get("scanned", [])
        require(isinstance(scanned, list) and len(scanned) > 0, "Semgrep scanned zero files")
        sarif = read_json(directory / "semgrep.sarif")
        require(isinstance(sarif, dict), "Invalid SARIF")
        runs = sarif.get("runs")
        require(isinstance(runs, list) and len(runs) > 0, "Missing SARIF runs")
        rules = 0
        count = 0
        for item in runs:
            rules += len(item.get("tool", {}).get("driver", {}).get("rules", []))
            require(isinstance(item.get("results"), list), "Missing SARIF results")
            count += len(item["results"])
            invocations = item.get("invocations", [])
            require(len(invocations) > 0, "Missing SARIF execution status")
            for invocation in invocations:
                require(invocation.get("executionSuccessful") is True, "SARIF scan failed")
                notices = invocation.get("toolExecutionNotifications", [])
                require(not any(n.get("level") in ("warning", "error") for n in notices),
                        "SARIF contains technical warnings/errors")
        require(rules > 0, "Semgrep loaded zero rules")
        require(count == len(data["results"]), "JSON/SARIF findings disagree")
        return {"findings": count, "files_scanned": len(scanned), "rules_in_report": rules}

    if tool == "trivy":
        data = read_json(directory / "trivy.json")
        require(isinstance(data, dict) and isinstance(data.get("Results"), list)
                and len(data["Results"]) > 0, "Missing Trivy scan targets")
        require(data.get("Metadata", {}).get("RepoDigests"), "Missing target image digest")
        if expected_target:
            require(expected_target in data["Metadata"]["RepoDigests"], "Trivy scanned the wrong image")
        counts = Counter()
        for item in data["Results"]:
            require(item.get("Target"), "Invalid Trivy target")
            vulnerabilities = item.get("Vulnerabilities", [])
            if vulnerabilities is None:
                vulnerabilities = []
            require(isinstance(vulnerabilities, list), "Invalid vulnerability list")
            for finding in vulnerabilities:
                require(finding.get("Severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"),
                        "Invalid Trivy severity")
                counts[finding["Severity"]] += 1
        db = read_json(directory / "trivy-db.json")
        require(isinstance(db, dict) and db.get("VulnerabilityDB"), "Missing Trivy DB metadata")
        return {"findings": sum(counts.values()), "severity": dict(counts)}

    if tool == "zap":
        data = read_json(directory / "zap.json")
        require(isinstance(data, dict), "Invalid ZAP report")
        sites = data.get("site")
        require(isinstance(sites, list) and len(sites) > 0, "ZAP has no scanned sites")
        require(any(s.get("@name") == "http://juice-shop:3000" for s in sites), "Wrong ZAP target")
        for site in sites:
            require(isinstance(site.get("alerts"), list), "Missing ZAP alert list")
        html = directory / "zap.html"
        require(html.is_file() and html.stat().st_size > 0, "Missing ZAP HTML report")
        return {"findings": sum(len(s["alerts"]) for s in sites), "scope": "unauthenticated passive baseline"}

    raise ValueError(f"Unknown scanner: {tool}")
