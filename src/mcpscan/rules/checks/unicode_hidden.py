"""Detection of zero-width and bidi control characters hidden in agent-facing text."""

from __future__ import annotations

from pathlib import Path

from mcpscan.models import Category, Finding, Location, Severity
from mcpscan.parsers import ParsedTarget
from mcpscan.rules import RuleInfo

RULES = [
    RuleInfo(
        "MCP102",
        "Hidden unicode characters in agent-facing text",
        Severity.CRITICAL,
        Category.PROMPT_INJECTION,
        "python",
    ),
]

ZERO_WIDTH = set(range(0x200B, 0x2010)) | {0x2060, 0xFEFF}
BIDI_CONTROLS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
HIDDEN = ZERO_WIDTH | BIDI_CONTROLS

CHECKED_FIELDS = {"tool_description", "skill_text"}


def _hidden_codepoints(text: str) -> list[tuple[int, str]]:
    """Return (line_offset, U+XXXX) pairs for each hidden character in *text*."""
    found: list[tuple[int, str]] = []
    line_offset = 0
    for char in text:
        if char == "\n":
            line_offset += 1
        elif ord(char) in HIDDEN:
            found.append((line_offset, f"U+{ord(char):04X}"))
    return found


def run(parsed: ParsedTarget) -> list[Finding]:
    findings: list[Finding] = []
    reported: set[tuple[Path, int]] = set()
    for unit in parsed.units:
        if unit.field not in CHECKED_FIELDS:
            continue
        hits = _hidden_codepoints(unit.text)
        if not hits:
            continue
        first_line = unit.line + hits[0][0]
        if (unit.file, first_line) in reported:
            continue
        reported.add((unit.file, first_line))
        codepoints = sorted({cp for _, cp in hits})
        where = f" in tool '{unit.context}'" if unit.context else ""
        findings.append(
            Finding(
                rule_id="MCP102",
                title="Hidden unicode characters in agent-facing text",
                description=(
                    f"Zero-width or bidi control characters found{where}: "
                    f"{', '.join(codepoints)}. These can hide instructions from human "
                    "review while remaining visible to the model."
                ),
                severity=Severity.CRITICAL,
                category=Category.PROMPT_INJECTION,
                location=Location(file=unit.file, line=first_line),
                remediation="Strip all zero-width and bidi control characters from the text.",
            )
        )
    return findings
