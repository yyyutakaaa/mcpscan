"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def vulnerable_server(fixtures: Path) -> Path:
    return fixtures / "vulnerable_server"


@pytest.fixture
def vulnerable_skill(fixtures: Path) -> Path:
    return fixtures / "vulnerable_skill"


@pytest.fixture
def clean_server(fixtures: Path) -> Path:
    return fixtures / "clean_server"
