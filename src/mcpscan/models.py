"""Core data models for mcpscan."""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank; higher means more severe."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


class Category(str, Enum):
    PROMPT_INJECTION = "prompt-injection"
    PERMISSIONS = "permissions"
    SECRETS = "secrets"
    EXFILTRATION = "exfiltration"
    SUPPLY_CHAIN = "supply-chain"


SNIPPET_MAX_LEN = 200

# Raw secret shapes that must never appear unmasked in any report snippet.
_SECRET_VALUE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xox[bpars]-[A-Za-z0-9-]{10,}"),
]
_URL_PASSWORD = re.compile(
    r"(?P<prefix>[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@'\"]+:)(?P<password>[^/\s:@'\"]+)(?=@)"
)


def mask_secret(value: str) -> str:
    """Mask a secret value: keep the first 4 characters, replace the rest with ****."""
    if len(value) <= 4:
        return "****"
    return value[:4] + "****"


def sanitize_snippet(text: str) -> str:
    """Mask known secret formats and URL passwords inside a report snippet."""
    for pattern in _SECRET_VALUE_PATTERNS:
        text = pattern.sub(lambda m: mask_secret(m.group(0)), text)
    return _URL_PASSWORD.sub(lambda m: m.group("prefix") + "****", text)


class Location(BaseModel):
    file: Path
    line: int | None = None
    column: int | None = None
    snippet: str | None = None

    @field_validator("snippet")
    @classmethod
    def _sanitize_and_truncate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = sanitize_snippet(value)
        if len(value) > SNIPPET_MAX_LEN:
            return value[: SNIPPET_MAX_LEN - 1] + "…"
        return value


class Finding(BaseModel):
    rule_id: str
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
