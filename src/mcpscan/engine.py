"""Scan orchestration: collect → parse → check → result."""

from __future__ import annotations

import time
from pathlib import Path

from mcpscan.collectors import collect_targets
from mcpscan.models import ScanResult, Severity
from mcpscan.parsers import parse_target
from mcpscan.rules import RuleSet


def scan(
    path: Path,
    rules_dirs: list[Path] | None = None,
    exclude: list[str] | None = None,
) -> ScanResult:
    start = time.monotonic()
    ruleset = RuleSet.load(rules_dirs)
    targets = collect_targets(path, exclude)
    findings = []
    for target in targets:
        findings.extend(ruleset.run(parse_target(target)))
    return ScanResult(
        targets_scanned=len(targets),
        findings=findings,
        duration_ms=int((time.monotonic() - start) * 1000),
    )


def worst_severity_met(result: ScanResult, threshold: Severity) -> bool:
    """True if any finding is at or above *threshold*."""
    return any(f.severity.rank >= threshold.rank for f in result.findings)
