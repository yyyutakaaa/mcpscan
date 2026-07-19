"""AST-based parser for Python source files."""

from __future__ import annotations

import ast

from mcpscan.models import Category, Finding, Location, ScanTarget, Severity
from mcpscan.parsers import ParsedTarget, PythonModule, StringConst, TextUnit, ToolDef

TOOL_DECORATOR_SUFFIXES = ("tool",)


def dotted_name(node: ast.expr, aliases: dict[str, str] | None = None) -> str | None:
    """Resolve an expression like ``subprocess.run`` to its dotted name, if possible."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        base = current.id
        if aliases and base in aliases:
            base = aliases[base]
        parts.append(base)
        return ".".join(reversed(parts))
    return None


def _decorator_name(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Call):
        dec = dec.func
    return dotted_name(dec)


def is_tool_decorated(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        name = _decorator_name(dec)
        if name and name.split(".")[-1] in TOOL_DECORATOR_SUFFIXES:
            return True
    return False


def collect_import_aliases(tree: ast.Module) -> dict[str, str]:
    """Map local names to the dotted names they alias (``import subprocess as sp``)."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def parse(target: ScanTarget) -> ParsedTarget:
    path = target.path
    parsed = ParsedTarget(target=target)
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError) as exc:
        reason = exc.msg if isinstance(exc, SyntaxError) else str(exc)
        parsed.parse_findings.append(
            Finding(
                rule_id="MCP000",
                title="Unparseable file",
                description=f"File could not be parsed and was skipped: {reason}",
                severity=Severity.INFO,
                category=Category.SUPPLY_CHAIN,
                location=Location(file=path, line=getattr(exc, "lineno", None) or 1),
                remediation="Fix the syntax so the file can be analyzed.",
            )
        )
        return parsed

    imports = sorted(collect_import_aliases(tree).values())
    tools: list[ToolDef] = []
    strings: list[StringConst] = []

    docstring_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            doc_line = node.lineno
            if doc is not None and node.body:
                doc_line = node.body[0].lineno
            if is_tool_decorated(node):
                if doc is not None:
                    docstring_lines.add(doc_line)
                params = [a.arg for a in node.args.args + node.args.kwonlyargs]
                tools.append(
                    ToolDef(
                        name=node.name,
                        params=params,
                        docstring=doc,
                        docstring_line=doc_line,
                        line=node.lineno,
                        node=node,
                    )
                )

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(StringConst(value=node.value, line=node.lineno))

    parsed.python = PythonModule(
        path=path, source=source, tree=tree, imports=imports, tools=tools, strings=strings
    )

    for tool in tools:
        if tool.docstring:
            parsed.units.append(
                TextUnit(
                    field="tool_description",
                    text=tool.docstring,
                    file=path,
                    line=tool.docstring_line,
                    context=tool.name,
                )
            )
    for const in strings:
        if const.line in docstring_lines:
            continue
        parsed.units.append(
            TextUnit(field="string_constant", text=const.value, file=path, line=const.line)
        )
    return parsed
