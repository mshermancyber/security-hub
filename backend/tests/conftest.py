"""Shared fixtures — isolated SQLite DB per test session."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# Tests run against the in-process app — disable bearer-token enforcement.
# Auth middleware is unit-tested separately.
os.environ.setdefault("SECHUB_INSECURE", "1")


@pytest.fixture(scope="session", autouse=True)
def _isolated_db():
    """Point SECHUB_DB at a temp file so tests don't touch dev data."""
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    os.environ["SECHUB_DB"] = tmp.name
    yield tmp.name
    try:
        Path(tmp.name).unlink()
    except FileNotFoundError:
        pass
