"""JSON reporter: the ScanResult model serialized verbatim."""

from __future__ import annotations

from mcpscan.models import ScanResult


def render(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)
