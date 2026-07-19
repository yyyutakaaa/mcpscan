"""Tests for file discovery and classification."""

from __future__ import annotations

import json
from pathlib import Path

from mcpscan.collectors import collect_targets


def _kinds(targets) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for t in targets:
        grouped.setdefault(t.kind, []).append(t.path.name)
    return grouped


def test_collects_config_and_python(vulnerable_server: Path) -> None:
    grouped = _kinds(collect_targets(vulnerable_server))
    assert grouped["mcp_config"] == ["claude_desktop_config.json"]
    assert grouped["python_source"] == ["server.py"]


def test_skill_directory_detected(vulnerable_skill: Path) -> None:
    targets = collect_targets(vulnerable_skill)
    assert [t.kind for t in targets] == ["skill"]
    assert targets[0].path == vulnerable_skill


def test_json_with_mcpservers_key_is_config(tmp_path: Path) -> None:
    config = tmp_path / "anything.json"
    config.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    other = tmp_path / "data.json"
    other.write_text(json.dumps({"foo": 1}), encoding="utf-8")
    grouped = _kinds(collect_targets(tmp_path))
    assert grouped["mcp_config"] == ["anything.json"]


def test_mcp_json_detected_by_name(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    grouped = _kinds(collect_targets(tmp_path))
    assert grouped["mcp_config"] == [".mcp.json"]


def test_skips_noise_directories(tmp_path: Path) -> None:
    for noisy in ("node_modules", ".git", ".venv", "__pycache__"):
        sub = tmp_path / noisy
        sub.mkdir()
        (sub / "x.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("print('ok')\n", encoding="utf-8")
    grouped = _kinds(collect_targets(tmp_path))
    assert grouped["python_source"] == ["keep.py"]


def test_exclude_glob(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("", encoding="utf-8")
    (tmp_path / "b.py").write_text("", encoding="utf-8")
    grouped = _kinds(collect_targets(tmp_path, exclude=["a.py"]))
    assert grouped["python_source"] == ["b.py"]


def test_single_file_paths(vulnerable_server: Path, vulnerable_skill: Path) -> None:
    assert collect_targets(vulnerable_server / "server.py")[0].kind == "python_source"
    assert (
        collect_targets(vulnerable_server / "claude_desktop_config.json")[0].kind == "mcp_config"
    )
    skill_target = collect_targets(vulnerable_skill / "SKILL.md")[0]
    assert skill_target.kind == "skill"
    assert skill_target.path == vulnerable_skill


def test_unclassifiable_file_yields_nothing(tmp_path: Path) -> None:
    readme = tmp_path / "README.rst"
    readme.write_text("nothing here", encoding="utf-8")
    assert collect_targets(readme) == []


def test_files_inside_skill_not_double_reported(tmp_path: Path) -> None:
    skill = tmp_path / "myskill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# s\n", encoding="utf-8")
    (skill / "notes.md").write_text("notes\n", encoding="utf-8")
    (skill / "helper.py").write_text("x = 1\n", encoding="utf-8")
    targets = collect_targets(tmp_path)
    kinds = sorted(t.kind for t in targets)
    assert kinds == ["python_source", "skill"]
