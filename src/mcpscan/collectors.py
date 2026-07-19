"""Discover and classify scannable files under a path."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from mcpscan.models import ScanTarget

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
MCP_CONFIG_NAMES = {"claude_desktop_config.json", ".mcp.json", "mcp.json"}
MAX_JSON_SNIFF_BYTES = 1_000_000


def _is_mcp_config(path: Path) -> bool:
    if path.name.lower() in MCP_CONFIG_NAMES:
        return True
    if path.suffix.lower() != ".json":
        return False
    try:
        if path.stat().st_size > MAX_JSON_SNIFF_BYTES:
            return False
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and "mcpServers" in data


def _is_excluded(path: Path, root: Path, exclude: list[str]) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    candidates = [str(rel), path.name, str(path)]
    return any(fnmatch.fnmatch(c, pattern) for pattern in exclude for c in candidates)


def _classify_file(path: Path) -> ScanTarget | None:
    if _is_mcp_config(path):
        return ScanTarget(kind="mcp_config", path=path)
    if path.suffix == ".py":
        return ScanTarget(kind="python_source", path=path)
    return None


def _has_skill_md(directory: Path) -> bool:
    try:
        return any(p.name.lower() == "skill.md" for p in directory.iterdir() if p.is_file())
    except OSError:
        return False


def collect_targets(path: Path, exclude: list[str] | None = None) -> list[ScanTarget]:
    """Walk *path* and return scan targets: MCP configs, Python files, and skill dirs.

    Files that live inside a skill directory are covered by the skill target and
    not re-emitted individually — except Python files, which also get AST checks.
    """
    exclude = exclude or []
    root = path if path.is_dir() else path.parent
    targets: list[ScanTarget] = []

    if path.is_file():
        if _is_excluded(path, root, exclude):
            return []
        if path.name.lower() == "skill.md":
            return [ScanTarget(kind="skill", path=path.parent)]
        target = _classify_file(path)
        return [target] if target else []

    skill_dirs: set[Path] = set()
    for current, dirnames, filenames in _walk(path):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not _is_excluded(current / d, root, exclude)
        )
        if _has_skill_md(current):
            skill_dirs.add(current)
            targets.append(ScanTarget(kind="skill", path=current))
        for name in sorted(filenames):
            file_path = current / name
            if _is_excluded(file_path, root, exclude):
                continue
            in_skill = any(sd in file_path.parents or sd == current for sd in skill_dirs)
            target = _classify_file(file_path)
            if target is None:
                continue
            if in_skill and target.kind != "python_source":
                continue
            targets.append(target)
    return targets


def _walk(path: Path):
    """os.walk-style generator yielding (Path, dirnames, filenames)."""
    import os

    for dirpath, dirnames, filenames in os.walk(path):
        yield Path(dirpath), dirnames, filenames
