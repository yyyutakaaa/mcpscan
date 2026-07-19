"""Parsers turn ScanTargets into normalized ParsedTargets that rules consume."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from mcpscan.models import Finding, ScanTarget


@dataclass
class TextUnit:
    """A piece of text a YAML rule can match against.

    ``line`` is the 1-based line in ``file`` where the text starts; matches
    inside the text add their newline offset to it.
    """

    field: str  # "tool_description" | "skill_text" | "server_args" | "string_constant" | "raw"
    text: str
    file: Path
    line: int = 1
    context: str | None = None  # e.g. tool or server name


@dataclass
class McpServer:
    name: str
    command: str | None
    args: list[str]
    env: dict[str, str]
    url: str | None
    file: Path
    line: int = 1
    env_lines: dict[str, int] = field(default_factory=dict)


@dataclass
class ToolDef:
    name: str
    params: list[str]
    docstring: str | None
    docstring_line: int
    line: int
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass
class StringConst:
    value: str
    line: int


@dataclass
class PythonModule:
    path: Path
    source: str
    tree: ast.Module
    imports: list[str]
    tools: list[ToolDef]
    strings: list[StringConst]


@dataclass
class SkillFile:
    path: Path
    text: str


@dataclass
class SkillData:
    directory: Path
    frontmatter: dict
    files: list[SkillFile]


@dataclass
class ParsedTarget:
    target: ScanTarget
    units: list[TextUnit] = field(default_factory=list)
    servers: list[McpServer] = field(default_factory=list)
    python: PythonModule | None = None
    skill: SkillData | None = None
    parse_findings: list[Finding] = field(default_factory=list)


def parse_target(target: ScanTarget) -> ParsedTarget:
    """Dispatch a scan target to the parser for its kind."""
    from mcpscan.parsers import mcp_config, python_source, skill_md

    if target.kind == "mcp_config":
        return mcp_config.parse(target)
    if target.kind == "python_source":
        return python_source.parse(target)
    return skill_md.parse(target)
