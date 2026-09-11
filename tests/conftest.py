"""Shared fixtures. Env vars are set before any ``scangrid`` import."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="scangrid-test-"))
os.environ.setdefault("SCANGRID_DATA_DIR", str(_TMP))
os.environ.setdefault("SCANGRID_API_TOKEN", "test-token-abc123")
os.environ.setdefault("SCANGRID_NOTIFY_BACKEND", "none")
os.environ.setdefault("SCANGRID_CVE_PROVIDER", "none")
os.environ.setdefault("SCANGRID_ALLOWLIST", "192.168.0.0/16,10.0.0.0/8")

import pytest  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402

from scangrid import allowlist  # noqa: E402
from scangrid.cve import reset_provider_cache  # noqa: E402
from scangrid.db import get_engine, init_db  # noqa: E402

TEST_TOKEN = "test-token-abc123"


@pytest.fixture(autouse=True)
def _fresh_db():
    allowlist.reload_cache()
    reset_provider_cache()
    engine = get_engine()
    SQLModel.metadata.drop_all(engine)
    init_db()
    yield
    SQLModel.metadata.drop_all(engine)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from scangrid.orchestrator.app import app

    c = TestClient(app)  # no lifespan -> no background scheduler
    c.headers.update({"Authorization": f"Bearer {TEST_TOKEN}"})
    return c


@pytest.fixture
def session():
    from scangrid.db import session_scope

    with session_scope() as s:
        yield s
