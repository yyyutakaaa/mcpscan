"""Tests for secret detection: known formats, entropy, and masking."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpscan.models import ScanTarget, mask_secret
from mcpscan.parsers import parse_target
from mcpscan.rules.checks import secrets


def _scan_env(tmp_path: Path, env: dict[str, str]):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"s": {"command": "run", "env": env}}}, indent=2),
        encoding="utf-8",
    )
    parsed = parse_target(ScanTarget(kind="mcp_config", path=config))
    return secrets.run(parsed)


@pytest.mark.parametrize(
    "value",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuv1234",
        "github_pat_11ABCDEFG0123456789abcdef",
        "sk-ant-api03-abcdef123456",
        "sk-proj-abcdefghijklmnopqrstuv",
        "xoxb-1234567890-abcdefghij",
    ],
)
def test_known_formats_are_critical(tmp_path: Path, value: str) -> None:
    findings = _scan_env(tmp_path, {"TOKEN": value})
    assert [f.rule_id for f in findings] == ["MCP501"]
    assert findings[0].severity.value == "critical"


def test_generic_api_key_assignment(tmp_path: Path) -> None:
    findings = _scan_env(tmp_path, {"API_KEY": "abcdef123456ghijkl"})
    assert [f.rule_id for f in findings] == ["MCP501"]


def test_entropy_only_hit_is_medium(tmp_path: Path) -> None:
    findings = _scan_env(tmp_path, {"SESSION": "wJalrXUtnFEMIK7MDENGbPxRfiCYzK9d2f8q"})
    assert [f.rule_id for f in findings] == ["MCP502"]
    assert findings[0].severity.value == "medium"


def test_low_entropy_value_ignored(tmp_path: Path) -> None:
    assert _scan_env(tmp_path, {"MODE": "production-production-production"}) == []


def test_short_value_ignored(tmp_path: Path) -> None:
    assert _scan_env(tmp_path, {"LOG_LEVEL": "info"}) == []


def test_secret_in_python_string(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    findings = secrets.run(parse_target(ScanTarget(kind="python_source", path=src)))
    assert [f.rule_id for f in findings] == ["MCP501"]
    assert findings[0].location.line == 1


def test_secret_in_skill_text(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("token: ghp_abcdefghijklmnopqrstuv1234\n", encoding="utf-8")
    findings = secrets.run(parse_target(ScanTarget(kind="skill", path=skill)))
    assert [f.rule_id for f in findings] == ["MCP501"]


def test_snippets_are_masked(tmp_path: Path) -> None:
    findings = _scan_env(tmp_path, {"AWS_KEY": "AKIAIOSFODNN7EXAMPLE"})
    snippet = findings[0].location.snippet or ""
    assert "AKIAIOSFODNN7EXAMPLE" not in snippet
    assert snippet.startswith("AKIA")
    assert "****" in snippet


def test_mask_secret_short_values() -> None:
    assert mask_secret("abc") == "****"
    assert mask_secret("abcdefgh") == "abcd****"


def test_shannon_entropy_bounds() -> None:
    assert secrets.shannon_entropy("") == 0.0
    assert secrets.shannon_entropy("aaaa") == 0.0
    assert secrets.shannon_entropy("wJalrXUtnFEMIK7MDENGbPxRfiCYzK9d2f8q") > 4.0
