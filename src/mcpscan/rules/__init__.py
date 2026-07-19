"""Rule loading and matching: declarative YAML rules plus Python check plugins."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

import yaml
from pydantic import BaseModel, field_validator

from mcpscan.models import Category, Finding, Location, Severity
from mcpscan.parsers import ParsedTarget

BUILTIN_RULES_DIR = Path(__file__).parent / "builtin"


class Matcher(BaseModel):
    type: Literal["regex", "substring"]
    pattern: str

    def compiled(self) -> re.Pattern[str]:
        if self.type == "regex":
            return re.compile(self.pattern)
        return re.compile(re.escape(self.pattern), re.IGNORECASE)


class YamlRule(BaseModel):
    id: str
    title: str
    severity: Severity
    category: Category
    applies_to: list[str]
    matchers: list[Matcher]
    description: str
    remediation: str | None = None

    @field_validator("matchers")
    @classmethod
    def _at_least_one(cls, v: list[Matcher]) -> list[Matcher]:
        if not v:
            raise ValueError("rule must define at least one matcher")
        return v


class Check(Protocol):
    """A Python check plugin: a module exposing run() and RULES metadata."""

    def run(self, parsed: ParsedTarget) -> list[Finding]: ...


@dataclass(frozen=True)
class RuleInfo:
    """Metadata row for `mcpscan rules`."""

    id: str
    title: str
    severity: Severity
    category: Category
    source: str  # "yaml" or "python"


def load_yaml_rules(extra_dirs: list[Path] | None = None) -> list[YamlRule]:
    """Load builtin YAML rules plus any rules from *extra_dirs*."""
    rules: list[YamlRule] = []
    dirs = [BUILTIN_RULES_DIR, *(extra_dirs or [])]
    for directory in dirs:
        if not directory.is_dir():
            raise FileNotFoundError(f"Rules directory not found: {directory}")
        for path in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data is None:
                continue
            rules.append(YamlRule.model_validate(data))
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise ValueError(f"Duplicate rule id: {rule.id}")
        seen.add(rule.id)
    return rules


def load_checks() -> list[Check]:
    from mcpscan.rules.checks import ast_checks, secrets, unicode_hidden

    return [secrets, ast_checks, unicode_hidden]


def _match_line(unit_text: str, unit_line: int, match_start: int) -> int:
    return unit_line + unit_text.count("\n", 0, match_start)


def _snippet_at(unit_text: str, match_start: int) -> str:
    line_start = unit_text.rfind("\n", 0, match_start) + 1
    line_end = unit_text.find("\n", match_start)
    if line_end == -1:
        line_end = len(unit_text)
    return unit_text[line_start:line_end].strip()


class RuleSet:
    def __init__(self, yaml_rules: list[YamlRule], checks: list[Check]) -> None:
        self.yaml_rules = yaml_rules
        self.checks = checks

    @classmethod
    def load(cls, extra_dirs: list[Path] | None = None) -> RuleSet:
        return cls(load_yaml_rules(extra_dirs), load_checks())

    def rule_infos(self) -> list[RuleInfo]:
        infos = [
            RuleInfo(
                "MCP000",
                "Unparseable file",
                Severity.INFO,
                Category.SUPPLY_CHAIN,
                "python",
            )
        ]
        infos.extend(
            RuleInfo(r.id, r.title, r.severity, r.category, "yaml") for r in self.yaml_rules
        )
        for check in self.checks:
            infos.extend(getattr(check, "RULES", []))
        return sorted(infos, key=lambda r: r.id)

    def run(self, parsed: ParsedTarget) -> list[Finding]:
        findings: list[Finding] = list(parsed.parse_findings)
        for rule in self.yaml_rules:
            findings.extend(self._run_yaml_rule(rule, parsed))
        for check in self.checks:
            findings.extend(check.run(parsed))
        return _dedupe(findings)

    def _run_yaml_rule(self, rule: YamlRule, parsed: ParsedTarget) -> list[Finding]:
        findings: list[Finding] = []
        wildcard = "any_text" in rule.applies_to
        for unit in parsed.units:
            if not wildcard and unit.field not in rule.applies_to:
                continue
            for matcher in rule.matchers:
                match = matcher.compiled().search(unit.text)
                if match is None:
                    continue
                line = _match_line(unit.text, unit.line, match.start())
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        description=rule.description.strip(),
                        severity=rule.severity,
                        category=rule.category,
                        location=Location(
                            file=unit.file,
                            line=line,
                            snippet=_snippet_at(unit.text, match.start()),
                        ),
                        remediation=rule.remediation,
                    )
                )
                break  # one finding per unit per rule
        return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, str(f.location.file), f.location.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique
