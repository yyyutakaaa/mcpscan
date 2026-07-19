# mcpscan

**Stop malicious MCP servers and poisoned skills before they reach your model.**

<!-- badges -->
[![Release](https://img.shields.io/github/v/release/yyyutakaaa/mcpscan?display_name=tag)](https://github.com/yyyutakaaa/mcpscan/releases)
[![CI](https://github.com/yyyutakaaa/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/yyyutakaaa/mcpscan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey)](LICENSE)

mcpscan scans your configs, Python code, and skills for the security problems that
actually matter: injection attacks, over-permissive tools, leaked secrets, and
exfiltration endpoints.

## 30 seconds to your first scan

```bash
pip install git+https://github.com/yyyutakaaa/mcpscan.git@v0.1.0
mcpscan .
```

It finds MCP configs, Python servers, and skill folders, then prints a report. Exits 1
if it finds anything at or above the threshold (default: `high`). Works straight in
CI — no glue needed. The package is installed directly from the tagged GitHub release.

## The rules

**Prompt injection (MCP101–105)**: Hidden unicode tricks, "ignore previous
instructions" type phrases, suspiciously long tool descriptions, instructions that try
to steer you away from other tools.

**Dangerous code (MCP201–204)**: eval/exec, subprocess calls fed by user input, shell
execution, file access without checking the path stays in bounds.

**Misconfigured servers (MCP210–211)**: `--allow-all` flags, filesystems rooted at `/`
or your home directory.

**Exfiltration (MCP301–302)**: POST/PUT to hardcoded external URLs, credentials in
URLs.

**Supply chain (MCP401–402)**: `curl | sh` patterns, pip installs without version
pinning.

**Secrets (MCP501–502)**: AWS keys, GitHub tokens, API credentials, high-entropy
environment variables.

Full rule table:

| ID | Severity | Category | Detects |
|---|---|---|---|
| MCP000 | info | supply-chain | File that could not be parsed (malformed JSON / Python) |
| MCP101 | high | prompt-injection | Instruction-override phrases in tool descriptions or skill text |
| MCP102 | critical | prompt-injection | Zero-width / bidi control characters hidden in agent-facing text |
| MCP103 | high | prompt-injection | "Always include/append/attach" + data nouns (files, keys, tokens, conversation) |
| MCP104 | medium | prompt-injection | Tool description longer than 1500 characters |
| MCP105 | high | prompt-injection | Tool description that references other tools' behavior |
| MCP201 | critical | permissions | `eval` / `exec` calls |
| MCP202 | critical | permissions | `subprocess` / `os.system` fed by tool parameters (command injection) |
| MCP203 | low | permissions | Shell command execution with constant or non-tool-derived arguments |
| MCP204 | medium | permissions | File access from tool input without a containment check (path traversal) |
| MCP210 | medium | permissions | Servers launched with `--allow-all` / `--dangerously-skip-permissions` / `--no-sandbox` style flags |
| MCP211 | medium | permissions | Filesystem server rooted at `/`, `~`, or an entire drive |
| MCP301 | high | exfiltration | HTTP POST/PUT to a hardcoded non-localhost URL inside a tool function |
| MCP302 | medium | exfiltration | URLs with embedded credentials (`https://user:pass@…`) |
| MCP401 | low | supply-chain | `curl … \| sh`, `wget … \| bash`, or `pip install` from a raw URL in skill text |
| MCP402 | low | supply-chain | Unpinned `pip install` commands in skill text (no `==`) |
| MCP501 | critical | secrets | Secrets in known formats (AWS, GitHub, OpenAI, Anthropic, Slack, generic API keys) |
| MCP502 | medium | secrets | High-entropy values in server `env` blocks |

Rule IDs are stable. Secrets are always masked (first 4 chars + `****`).

## Running it

```
mcpscan PATH [OPTIONS]

Options:
  --format [terminal|json|sarif]   (default: terminal)
  --output FILE                    write report to a file
  --fail-on [critical|high|...]    (default: high)
  --rules DIR                      your own rules directory
  --exclude GLOB                   skip these files (repeatable)
  --version

Commands:
  rules                            list all loaded rules
```

Exit codes: `0` = no findings, `1` = findings at/above threshold, `2` = error.

## Detection model and limitations

mcpscan is a static, heuristic scanner. A finding identifies risky code or text that
deserves review; it does not prove that a server is malicious. Conversely, a clean
scan does not prove that a server is safe.

The Python checks perform local analysis inside MCP tool functions, including direct
parameter use and propagation through local assignments. They do not currently follow
data through helper functions, imports, containers, or runtime-generated code. Path
containment checks are recognized syntactically, so reviewers should still verify that
the check protects the same path and base directory used by the file operation.

## GitHub integration

```yaml
name: mcpscan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: yyyutakaaa/mcpscan@v0.1.0
        with:
          path: .
          fail-on: high
```

Results show up in Security → Code scanning.

## Adding your own rules

Drop a YAML file in a directory and pass `--rules ./my-rules`:

```yaml
id: ORG001
title: Internal hostname in skill text
severity: high
category: exfiltration
applies_to: [skill_text]          # tool_description | skill_text | server_args | string_constant | any_text
matchers:                          # rule fires if ANY matcher matches
  - type: regex
    pattern: "(?i)corp\\.internal\\.example"
  - type: substring                # substring matchers are case-insensitive
    pattern: staging-db
description: Leaks infrastructure details.
remediation: Use environment variables instead.
```

For stuff that needs AST analysis or entropy checking, write a Python module in
`src/mcpscan/rules/checks/`. Implement `run(parsed: ParsedTarget) -> list[Finding]`.

## Future

- Scanning git URLs directly
- Node.js / TypeScript support
- Runtime proxy to watch live MCP traffic
- LLM-assisted semantic checks

## Contributing

If you've spotted a bad MCP server or poisoned skill in the wild, you can usually turn
the pattern into a five-line rule (see above). Submit it with a test fixture and an
assertion that it fires — we'll take a look.

To hack on it locally:

```bash
git clone https://github.com/yyyutakaaa/mcpscan && cd mcpscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
