"""Minimal SARIF 2.1.0 reporter for CI code-scanning integration."""

from __future__ import annotations

import json

from mcpscan import __version__
from mcpscan.models import ScanResult, Severity

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(result: ScanResult) -> str:
    rules_seen: dict[str, dict] = {}
    results: list[dict] = []
    for finding in result.findings:
        rules_seen.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                **(
                    {"help": {"text": finding.remediation}}
                    if finding.remediation
                    else {}
                ),
            },
        )
        region: dict = {}
        if finding.location.line is not None:
            region["startLine"] = finding.location.line
        if finding.location.column is not None:
            region["startColumn"] = finding.location.column + 1
        if finding.location.snippet:
            region["snippet"] = {"text": finding.location.snippet}
        physical: dict = {
            "artifactLocation": {"uri": finding.location.file.as_posix()},
        }
        if region:
            physical["region"] = region
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": f"{finding.title}: {finding.description}"},
                "locations": [{"physicalLocation": physical}],
            }
        )

    document = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpscan",
                        "version": __version__,
                        "informationUri": "https://github.com/mcpscan/mcpscan",
                        "rules": sorted(rules_seen.values(), key=lambda r: r["id"]),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
