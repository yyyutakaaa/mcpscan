"""Tests for terminal, JSON, and SARIF reporters."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from mcpscan.engine import scan
from mcpscan.models import ScanResult
from mcpscan.reporters import json_reporter, sarif_reporter, terminal

RAW_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def test_json_round_trips(vulnerable_server: Path) -> None:
    result = scan(vulnerable_server)
    rendered = json_reporter.render(result)
    restored = ScanResult.model_validate_json(rendered)
    assert restored.targets_scanned == result.targets_scanned
    assert [f.rule_id for f in restored.findings] == [f.rule_id for f in result.findings]


def test_json_masks_secrets(vulnerable_server: Path) -> None:
    rendered = json_reporter.render(scan(vulnerable_server))
    assert RAW_AWS_KEY not in rendered
    assert "AKIA****" in rendered


def test_sarif_structure(vulnerable_server: Path) -> None:
    result = scan(vulnerable_server)
    document = json.loads(sarif_reporter.render(result))
    assert document["version"] == "2.1.0"
    assert "sarif-schema-2.1.0" in document["$schema"]
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcpscan"
    assert len(run["results"]) == len(result.findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for sarif_result in run["results"]:
        assert sarif_result["ruleId"] in rule_ids
        assert sarif_result["level"] in {"error", "warning", "note"}
        assert sarif_result["message"]["text"]
        location = sarif_result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"]


def test_sarif_level_mapping(vulnerable_server: Path) -> None:
    result = scan(vulnerable_server)
    document = json.loads(sarif_reporter.render(result))
    by_rule = {r["ruleId"]: r["level"] for r in document["runs"][0]["results"]}
    assert by_rule["MCP501"] == "error"  # critical
    assert by_rule["MCP301"] == "error"  # high
    assert by_rule["MCP502"] == "warning"  # medium


def test_sarif_masks_secrets(vulnerable_server: Path) -> None:
    rendered = sarif_reporter.render(scan(vulnerable_server))
    assert RAW_AWS_KEY not in rendered


def test_terminal_masks_secrets_and_shows_summary(vulnerable_server: Path) -> None:
    console = Console(record=True, width=100)
    terminal.render(scan(vulnerable_server), vulnerable_server, console)
    text = console.export_text()
    assert RAW_AWS_KEY not in text
    assert "AKIA****" in text
    assert "MCP501" in text
    assert "Summary" in text
    assert "worst severity" in text


def test_terminal_clean_verdict(clean_server: Path) -> None:
    console = Console(record=True, width=100)
    terminal.render(scan(clean_server), clean_server, console)
    text = console.export_text()
    assert "No issues found" in text


def test_url_password_masked_in_snippet(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "Connect to https://admin:hunter2@db.example.com/prod\n", encoding="utf-8"
    )
    rendered = json_reporter.render(scan(tmp_path))
    assert "hunter2" not in rendered
    assert "admin:****@" in rendered
