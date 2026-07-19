"""Parser for skill directories: SKILL.md plus sibling text files."""

from __future__ import annotations

from pathlib import Path

import yaml

from mcpscan.models import Category, Finding, Location, ScanTarget, Severity
from mcpscan.parsers import ParsedTarget, SkillData, SkillFile, TextUnit

SIBLING_SUFFIXES = {".md", ".txt", ".py", ".sh", ".json", ".yaml", ".yml"}
MAX_FILE_BYTES = 1_000_000


def _parse_frontmatter(text: str) -> tuple[dict, int]:
    """Return (frontmatter dict, line offset of the body start)."""
    if not text.startswith("---"):
        return {}, 0
    lines = text.splitlines()
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            block = "\n".join(lines[1:i])
            try:
                data = yaml.safe_load(block)
            except yaml.YAMLError:
                return {}, 0
            return (data if isinstance(data, dict) else {}), i + 1
    return {}, 0


def parse(target: ScanTarget) -> ParsedTarget:
    directory = target.path
    parsed = ParsedTarget(target=target)
    files: list[SkillFile] = []
    frontmatter: dict = {}

    skill_md_path: Path | None = None
    siblings: list[Path] = []
    try:
        for p in sorted(directory.iterdir()):
            if not p.is_file():
                continue
            if p.name.lower() == "skill.md" and skill_md_path is None:
                skill_md_path = p
            elif p.suffix.lower() in SIBLING_SUFFIXES:
                siblings.append(p)
    except OSError as exc:
        parsed.parse_findings.append(
            Finding(
                rule_id="MCP000",
                title="Unparseable file",
                description=f"Skill directory could not be read: {exc}",
                severity=Severity.INFO,
                category=Category.SUPPLY_CHAIN,
                location=Location(file=directory),
                remediation="Ensure the skill directory is readable.",
            )
        )
        return parsed

    for p in ([skill_md_path] if skill_md_path else []) + siblings:
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append(SkillFile(path=p, text=text))
        if p == skill_md_path:
            frontmatter, _ = _parse_frontmatter(text)
        parsed.units.append(TextUnit(field="skill_text", text=text, file=p, line=1))

    parsed.skill = SkillData(directory=directory, frontmatter=frontmatter, files=files)
    return parsed
