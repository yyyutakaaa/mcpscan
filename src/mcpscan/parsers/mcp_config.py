"""Parser for MCP config JSON files (claude_desktop_config.json, .mcp.json, mcp.json)."""

from __future__ import annotations

import json

from mcpscan.models import Category, Finding, Location, ScanTarget, Severity
from mcpscan.parsers import McpServer, ParsedTarget, TextUnit


def _find_line(raw_lines: list[str], needle: str, start: int = 0) -> int:
    """Return the 1-based line number of the first line containing *needle*."""
    quoted = f'"{needle}"'
    for i, line in enumerate(raw_lines[start:], start=start):
        if quoted in line:
            return i + 1
    return 1


def _unparseable(target: ScanTarget, reason: str) -> ParsedTarget:
    finding = Finding(
        rule_id="MCP000",
        title="Unparseable file",
        description=f"File could not be parsed and was skipped: {reason}",
        severity=Severity.INFO,
        category=Category.SUPPLY_CHAIN,
        location=Location(file=target.path, line=1),
        remediation="Fix the syntax so the file can be analyzed.",
    )
    return ParsedTarget(target=target, parse_findings=[finding])


def parse(target: ScanTarget) -> ParsedTarget:
    path = target.path
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _unparseable(target, str(exc))

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _unparseable(target, f"invalid JSON ({exc.msg} at line {exc.lineno})")

    parsed = ParsedTarget(target=target)
    parsed.units.append(TextUnit(field="raw", text=raw, file=path, line=1))

    servers_obj = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers_obj, dict):
        return parsed

    raw_lines = raw.splitlines()
    for name, spec in servers_obj.items():
        if not isinstance(spec, dict):
            continue
        line = _find_line(raw_lines, name)
        env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
        env = {str(k): str(v) for k, v in env.items()}
        args_raw = spec.get("args") if isinstance(spec.get("args"), list) else []
        args = [str(a) for a in args_raw]
        server = McpServer(
            name=name,
            command=str(spec["command"]) if spec.get("command") is not None else None,
            args=args,
            env=env,
            url=str(spec["url"]) if spec.get("url") is not None else None,
            file=path,
            line=line,
            env_lines={key: _find_line(raw_lines, key, start=line - 1) for key in env},
        )
        parsed.servers.append(server)
        args_text = " ".join(filter(None, [server.command, *server.args]))
        if args_text:
            parsed.units.append(
                TextUnit(field="server_args", text=args_text, file=path, line=line, context=name)
            )
    return parsed
