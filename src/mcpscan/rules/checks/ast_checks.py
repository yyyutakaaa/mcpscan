"""AST-based checks: dangerous calls, command injection, path traversal, exfiltration."""

from __future__ import annotations

import ast
from urllib.parse import urlparse

from mcpscan.models import Category, Finding, Location, Severity
from mcpscan.parsers import ParsedTarget, PythonModule, ToolDef
from mcpscan.parsers.python_source import collect_import_aliases, dotted_name
from mcpscan.rules import RuleInfo

RULES = [
    RuleInfo("MCP201", "eval/exec call", Severity.CRITICAL, Category.PERMISSIONS, "python"),
    RuleInfo(
        "MCP202",
        "Unsanitized command execution from tool input",
        Severity.CRITICAL,
        Category.PERMISSIONS,
        "python",
    ),
    RuleInfo(
        "MCP203",
        "Shell command execution",
        Severity.LOW,
        Category.PERMISSIONS,
        "python",
    ),
    RuleInfo(
        "MCP204",
        "File access from tool input without containment check",
        Severity.MEDIUM,
        Category.PERMISSIONS,
        "python",
    ),
    RuleInfo(
        "MCP301",
        "Potential exfiltration endpoint",
        Severity.HIGH,
        Category.EXFILTRATION,
        "python",
    ),
]

SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen", "getoutput"}
HTTP_POST_NAMES = {"requests.post", "requests.put", "httpx.post", "httpx.put"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", ""}
CONTAINMENT_ATTRS = {"is_relative_to", "commonpath", "startswith", "relative_to"}


def _uses_param(node: ast.expr, params: set[str]) -> bool:
    """True if *node* is a Name in *params* or an f-string/expression containing one."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in params:
            return True
    return False


def _call_args(call: ast.Call) -> list[ast.expr]:
    return list(call.args) + [kw.value for kw in call.keywords if kw.value is not None]


def _all_constant(call: ast.Call) -> bool:
    return all(
        all(isinstance(sub, (ast.Constant, ast.List, ast.Tuple)) for sub in ast.walk(arg))
        for arg in _call_args(call)
    )


def _has_containment_check(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(sub, ast.Attribute) and sub.attr in CONTAINMENT_ATTRS
        for sub in ast.walk(func)
    )


def _snippet(py: PythonModule, node: ast.AST) -> str:
    lines = py.source.splitlines()
    lineno = getattr(node, "lineno", 1)
    return lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""


def _finding(
    py: PythonModule,
    node: ast.AST,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    category: Category,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        location=Location(
            file=py.path,
            line=getattr(node, "lineno", None),
            column=getattr(node, "col_offset", None),
            snippet=_snippet(py, node),
        ),
        remediation=remediation,
    )


def _url_of(call: ast.Call) -> str | None:
    candidates: list[ast.expr] = []
    if call.args:
        candidates.append(call.args[0])
    candidates.extend(kw.value for kw in call.keywords if kw.arg == "url")
    for cand in candidates:
        if isinstance(cand, ast.Constant) and isinstance(cand.value, str):
            return cand.value
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, py: PythonModule, tools: dict[int, ToolDef], aliases: dict[str, str]):
        self.py = py
        self.tools = tools
        self.aliases = aliases
        self.func_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self.findings: list[Finding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func_stack.append(node)
        self.generic_visit(node)
        self.func_stack.pop()

    def _enclosing_tool(self) -> ToolDef | None:
        for func in reversed(self.func_stack):
            tool = self.tools.get(id(func))
            if tool is not None:
                return tool
        return None

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func, self.aliases)
        if name in ("eval", "exec", "builtins.eval", "builtins.exec"):
            self._emit_eval(node, name)
        elif name == "os.system" or (
            name and name.startswith("subprocess.") and name.split(".")[-1] in SUBPROCESS_FUNCS
        ):
            self._check_command(node, name)
        elif name in ("open", "pathlib.Path", "Path"):
            self._check_file_access(node, name)
        elif name in HTTP_POST_NAMES or (
            name == "urllib.request.urlopen"
            and any(kw.arg == "data" for kw in node.keywords)
        ):
            self._check_http(node, name)
        self.generic_visit(node)

    def _emit_eval(self, node: ast.Call, name: str) -> None:
        self.findings.append(
            _finding(
                self.py,
                node,
                "MCP201",
                "eval/exec call",
                f"Call to {name}() executes arbitrary Python code at runtime.",
                Severity.CRITICAL,
                Category.PERMISSIONS,
                "Remove eval/exec; use explicit parsing or dispatch instead.",
            )
        )

    def _check_command(self, node: ast.Call, name: str) -> None:
        tool = self._enclosing_tool()
        params = set(tool.params) if tool else set()
        if tool and any(_uses_param(arg, params) for arg in _call_args(node)):
            self.findings.append(
                _finding(
                    self.py,
                    node,
                    "MCP202",
                    "Unsanitized command execution from tool input",
                    f"{name}() is called with input taken from the parameters of tool "
                    f"'{tool.name}', allowing command injection.",
                    Severity.CRITICAL,
                    Category.PERMISSIONS,
                    "Never interpolate tool input into shell commands; pass argument "
                    "lists without shell=True and validate inputs.",
                )
            )
        else:
            detail = (
                "with constant arguments only"
                if _all_constant(node)
                else "with arguments not derived from tool parameters"
            )
            self.findings.append(
                _finding(
                    self.py,
                    node,
                    "MCP203",
                    "Shell command execution",
                    f"{name}() is called {detail}. Review that this command is intended.",
                    Severity.LOW,
                    Category.PERMISSIONS,
                    "Prefer library calls over shelling out where possible.",
                )
            )

    def _check_file_access(self, node: ast.Call, name: str) -> None:
        tool = self._enclosing_tool()
        if tool is None:
            return
        params = set(tool.params)
        if not any(_uses_param(arg, params) for arg in _call_args(node)):
            return
        if _has_containment_check(tool.node):
            return
        self.findings.append(
            _finding(
                self.py,
                node,
                "MCP204",
                "File access from tool input without containment check",
                f"{name}() uses a path from the parameters of tool '{tool.name}' without a "
                "visible containment check, enabling path traversal.",
                Severity.MEDIUM,
                Category.PERMISSIONS,
                "Resolve the path and verify it stays inside an allowed base directory "
                "(Path.is_relative_to) before use.",
            )
        )

    def _check_http(self, node: ast.Call, name: str) -> None:
        if self._enclosing_tool() is None:
            return
        url = _url_of(node)
        if url is None:
            return
        host = urlparse(url).hostname or ""
        if host in LOCAL_HOSTS:
            return
        self.findings.append(
            _finding(
                self.py,
                node,
                "MCP301",
                "Potential exfiltration endpoint",
                f"{name}() sends data to hardcoded external endpoint {url} from inside a "
                "tool function.",
                Severity.HIGH,
                Category.EXFILTRATION,
                "Tools should not push data to hardcoded external hosts; make endpoints "
                "explicit configuration and document them.",
            )
        )


def run(parsed: ParsedTarget) -> list[Finding]:
    py = parsed.python
    if py is None:
        return []
    visitor = _Visitor(py, {id(t.node): t for t in py.tools}, collect_import_aliases(py.tree))
    visitor.visit(py.tree)
    return visitor.findings
