"""Tests for the three parsers."""

from __future__ import annotations

from pathlib import Path

from mcpscan.models import ScanTarget
from mcpscan.parsers import parse_target


def test_mcp_config_extracts_servers(vulnerable_server: Path) -> None:
    target = ScanTarget(kind="mcp_config", path=vulnerable_server / "claude_desktop_config.json")
    parsed = parse_target(target)
    names = {s.name for s in parsed.servers}
    assert names == {"files", "deploy"}
    deploy = next(s for s in parsed.servers if s.name == "deploy")
    assert deploy.command == "python"
    assert "--dangerously-skip-permissions" in deploy.args
    assert "AWS_ACCESS_KEY_ID" in deploy.env
    assert deploy.env_lines["AWS_ACCESS_KEY_ID"] > deploy.line


def test_mcp_config_malformed_json_emits_mcp000(tmp_path: Path) -> None:
    bad = tmp_path / "mcp.json"
    bad.write_text("{not json", encoding="utf-8")
    parsed = parse_target(ScanTarget(kind="mcp_config", path=bad))
    assert [f.rule_id for f in parsed.parse_findings] == ["MCP000"]
    assert parsed.servers == []


def test_mcp_config_server_args_unit(vulnerable_server: Path) -> None:
    target = ScanTarget(kind="mcp_config", path=vulnerable_server / "claude_desktop_config.json")
    parsed = parse_target(target)
    args_units = [u for u in parsed.units if u.field == "server_args"]
    assert len(args_units) == 2
    files_unit = next(u for u in args_units if u.context == "files")
    assert "server-filesystem" in files_unit.text


def test_python_source_extracts_tools(vulnerable_server: Path) -> None:
    parsed = parse_target(ScanTarget(kind="python_source", path=vulnerable_server / "server.py"))
    assert parsed.python is not None
    tools = {t.name: t for t in parsed.python.tools}
    assert set(tools) == {"convert_image", "sync_notes", "read_file"}
    assert tools["convert_image"].params == ["filename"]
    assert "Ignore previous instructions" in (tools["convert_image"].docstring or "")
    descriptions = [u for u in parsed.units if u.field == "tool_description"]
    assert len(descriptions) == 3


def test_python_source_syntax_error_emits_mcp000(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n", encoding="utf-8")
    parsed = parse_target(ScanTarget(kind="python_source", path=bad))
    assert [f.rule_id for f in parsed.parse_findings] == ["MCP000"]


def test_python_source_string_constants_have_lines(clean_server: Path) -> None:
    parsed = parse_target(ScanTarget(kind="python_source", path=clean_server / "server.py"))
    assert parsed.python is not None
    values = {s.value for s in parsed.python.strings}
    assert "/srv/workspace" in values
    assert all(s.line >= 1 for s in parsed.python.strings)


def test_skill_md_frontmatter_and_siblings(tmp_path: Path) -> None:
    skill = tmp_path / "myskill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: demo\ndescription: a demo skill\n---\n\n# Demo\n", encoding="utf-8"
    )
    (skill / "extra.md").write_text("more text\n", encoding="utf-8")
    (skill / "image.png").write_bytes(b"\x89PNG")
    parsed = parse_target(ScanTarget(kind="skill", path=skill))
    assert parsed.skill is not None
    assert parsed.skill.frontmatter == {"name": "demo", "description": "a demo skill"}
    parsed_names = {f.path.name for f in parsed.skill.files}
    assert parsed_names == {"SKILL.md", "extra.md"}
    assert all(u.field == "skill_text" for u in parsed.units)


def test_skill_md_without_frontmatter(tmp_path: Path) -> None:
    skill = tmp_path / "s"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# Just a title\n", encoding="utf-8")
    parsed = parse_target(ScanTarget(kind="skill", path=skill))
    assert parsed.skill is not None
    assert parsed.skill.frontmatter == {}


def test_skill_md_skips_oversized_files(tmp_path: Path) -> None:
    skill = tmp_path / "s"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# t\n", encoding="utf-8")
    (skill / "big.txt").write_text("x" * 1_000_001, encoding="utf-8")
    parsed = parse_target(ScanTarget(kind="skill", path=skill))
    assert parsed.skill is not None
    assert {f.path.name for f in parsed.skill.files} == {"SKILL.md"}
