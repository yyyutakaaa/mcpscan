"""Secret detection: known key formats plus Shannon entropy on config env values."""

from __future__ import annotations

import math
import re

from mcpscan.models import Category, Finding, Location, Severity, mask_secret
from mcpscan.parsers import ParsedTarget
from mcpscan.rules import RuleInfo

RULES = [
    RuleInfo(
        "MCP501",
        "Secret with a known key format",
        Severity.CRITICAL,
        Category.SECRETS,
        "python",
    ),
    RuleInfo(
        "MCP502",
        "High-entropy value in server environment",
        Severity.MEDIUM,
        Category.SECRETS,
        "python",
    ),
]

KNOWN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}")),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"xox[bpars]-[A-Za-z0-9-]{10,}")),
    (
        "Generic API key assignment",
        re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    ),
]

ENTROPY_THRESHOLD = 4.0
ENTROPY_MIN_LEN = 20


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _known_format(value: str) -> str | None:
    for label, pattern in KNOWN_PATTERNS:
        if pattern.search(value):
            return label
    return None


def _finding_known(label: str, value: str, file, line) -> Finding:
    return Finding(
        rule_id="MCP501",
        title="Secret with a known key format",
        description=f"A value matching a known secret format ({label}) is committed here.",
        severity=Severity.CRITICAL,
        category=Category.SECRETS,
        location=Location(file=file, line=line, snippet=mask_secret(value)),
        remediation="Revoke the credential and load it from the environment at runtime.",
    )


def run(parsed: ParsedTarget) -> list[Finding]:
    findings: list[Finding] = []

    for server in parsed.servers:
        for key, value in server.env.items():
            line = server.env_lines.get(key, server.line)
            label = _known_format(value) or _known_format(f"{key}={value}")
            if label:
                findings.append(_finding_known(label, value, server.file, line))
                continue
            if (
                len(value) >= ENTROPY_MIN_LEN
                and value.isalnum()
                and shannon_entropy(value) > ENTROPY_THRESHOLD
            ):
                findings.append(
                    Finding(
                        rule_id="MCP502",
                        title="High-entropy value in server environment",
                        description=(
                            f"Environment variable {key} holds a high-entropy value that "
                            "looks like a credential."
                        ),
                        severity=Severity.MEDIUM,
                        category=Category.SECRETS,
                        location=Location(
                            file=server.file, line=line, snippet=mask_secret(value)
                        ),
                        remediation="Keep credentials out of config files; inject them at runtime.",
                    )
                )

    if parsed.python is not None:
        for const in parsed.python.strings:
            label = _known_format(const.value)
            if label:
                findings.append(
                    _finding_known(label, const.value, parsed.python.path, const.line)
                )

    if parsed.skill is not None:
        for skill_file in parsed.skill.files:
            for i, line_text in enumerate(skill_file.text.splitlines(), start=1):
                label = _known_format(line_text)
                if label:
                    findings.append(_finding_known(label, line_text.strip(), skill_file.path, i))
    return findings
