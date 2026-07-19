"""End-to-end CLI tests via typer's CliRunner."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from typer.testing import CliRunner

from mcpscan import __version__
from mcpscan.cli import app
from mcpscan.models import ScanResult

runner = CliRunner()


def test_scan_vulnerable_exits_1_with_findings(vulnerable_server: Path) -> None:
    result = runner.invoke(app, [str(vulnerable_server)])
    assert result.exit_code == 1
    assert "MCP501" in result.output
    assert "worst severity" in result.output


def test_scan_clean_exits_0(clean_server: Path) -> None:
    result = runner.invoke(app, [str(clean_server)])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_vulnerable_server_has_at_least_5_findings(vulnerable_server: Path) -> None:
    result = runner.invoke(app, [str(vulnerable_server), "--format", "json"])
    assert result.exit_code == 1
    parsed = ScanResult.model_validate_json(result.output)
    assert len(parsed.findings) >= 5


def test_fail_on_threshold(vulnerable_skill: Path) -> None:
    # worst finding in the skill fixture is high
    assert runner.invoke(app, [str(vulnerable_skill), "--fail-on", "high"]).exit_code == 1
    assert runner.invoke(app, [str(vulnerable_skill), "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(app, [str(vulnerable_skill), "--fail-on", "low"]).exit_code == 1


def test_json_output_to_file(vulnerable_server: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, [str(vulnerable_server), "--format", "json", "--output", str(out)]
    )
    assert result.exit_code == 1
    parsed = ScanResult.model_validate_json(out.read_text(encoding="utf-8"))
    assert parsed.targets_scanned == 2


def test_sarif_output(vulnerable_server: Path) -> None:
    result = runner.invoke(app, [str(vulnerable_server), "--format", "sarif"])
    assert result.exit_code == 1
    document = json.loads(result.output)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"] == "mcpscan"


def test_terminal_output_to_file(clean_server: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    result = runner.invoke(app, [str(clean_server), "--output", str(out)])
    assert result.exit_code == 0
    assert "No issues found" in out.read_text(encoding="utf-8")


def test_nonexistent_path_exits_2() -> None:
    result = runner.invoke(app, ["/definitely/not/a/real/path"])
    assert result.exit_code == 2


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_rules_subcommand_lists_rules() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    for rule_id in ("MCP101", "MCP102", "MCP301", "MCP501"):
        assert rule_id in result.output


def test_exclude_option(vulnerable_server: Path) -> None:
    result = runner.invoke(
        app,
        [
            str(vulnerable_server),
            "--format", "json",
            "--exclude", "server.py",
            "--exclude", "*.json",
        ],
    )
    assert result.exit_code == 0
    parsed = ScanResult.model_validate_json(result.output)
    assert parsed.targets_scanned == 0


def test_custom_rules_dir(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "org.yaml").write_text(
        textwrap.dedent(
            """
            id: ORG100
            title: Custom marker
            severity: critical
            category: prompt-injection
            applies_to: [skill_text]
            matchers:
              - type: substring
                pattern: verboten
            description: Custom rule for tests.
            """
        ),
        encoding="utf-8",
    )
    project = tmp_path / "project"
    skill = project / "skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("this is verboten content\n", encoding="utf-8")
    result = runner.invoke(
        app, [str(project), "--rules", str(rules_dir), "--format", "json"]
    )
    assert result.exit_code == 1
    parsed = ScanResult.model_validate_json(result.output)
    assert "ORG100" in {f.rule_id for f in parsed.findings}


def test_invalid_rules_dir_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, [str(tmp_path), "--rules", str(tmp_path / "missing")])
    assert result.exit_code == 2


def test_scan_single_file(vulnerable_server: Path) -> None:
    result = runner.invoke(app, [str(vulnerable_server / "server.py"), "--format", "json"])
    assert result.exit_code == 1
    parsed = ScanResult.model_validate_json(result.output)
    assert parsed.targets_scanned == 1
    assert all(
        f.location.file.name == "server.py" for f in parsed.findings
    )
