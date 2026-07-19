"""Tests for hidden unicode character detection."""

from __future__ import annotations

import textwrap
from pathlib import Path

from mcpscan.models import ScanTarget
from mcpscan.parsers import parse_target
from mcpscan.rules.checks import unicode_hidden


def _run_skill(tmp_path: Path, text: str):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(text, encoding="utf-8")
    return unicode_hidden.run(parse_target(ScanTarget(kind="skill", path=skill)))


def test_zero_width_space_detected(tmp_path: Path) -> None:
    findings = _run_skill(tmp_path, "hello​world\n")
    assert [f.rule_id for f in findings] == ["MCP102"]
    assert "U+200B" in findings[0].description
    assert findings[0].severity.value == "critical"


def test_bidi_override_detected(tmp_path: Path) -> None:
    findings = _run_skill(tmp_path, "line one\nsee ‮reversed‬ text\n")
    assert len(findings) == 1
    assert "U+202E" in findings[0].description
    assert findings[0].location.line == 2


def test_multiple_codepoints_reported_once(tmp_path: Path) -> None:
    findings = _run_skill(tmp_path, "a​ b﻿ c⁦\n")
    assert len(findings) == 1
    for codepoint in ("U+200B", "U+FEFF", "U+2066"):
        assert codepoint in findings[0].description


def test_clean_text_not_flagged(tmp_path: Path) -> None:
    assert _run_skill(tmp_path, "perfectly normal text, even with émojis 🎉\n") == []


def test_hidden_char_in_tool_docstring(tmp_path: Path) -> None:
    src = tmp_path / "server.py"
    src.write_text(
        textwrap.dedent(
            '''
            @mcp.tool()
            def sneaky(x: str) -> str:
                """Perfectly innocent​ description."""
                return x
            '''
        ),
        encoding="utf-8",
    )
    findings = unicode_hidden.run(parse_target(ScanTarget(kind="python_source", path=src)))
    assert [f.rule_id for f in findings] == ["MCP102"]
    assert "sneaky" in findings[0].description


def test_string_constants_not_checked(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text('DATA = "has​hidden"\n', encoding="utf-8")
    findings = unicode_hidden.run(parse_target(ScanTarget(kind="python_source", path=src)))
    assert findings == []


def test_fixture_docstring_zero_width(vulnerable_server: Path) -> None:
    parsed = parse_target(
        ScanTarget(kind="python_source", path=vulnerable_server / "server.py")
    )
    findings = unicode_hidden.run(parsed)
    assert [f.rule_id for f in findings] == ["MCP102"]
    assert "convert_image" in findings[0].description
