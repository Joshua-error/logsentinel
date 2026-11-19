from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from logsentinel.parsers import Event

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 11, 18, 2, 0, 0)


def ev(seconds: float, kind: str = "ssh_failed", ip: str = "203.0.113.5", **kw) -> Event:
    """Build a test event ``seconds`` after T0."""
    source = kw.pop("source", {"ssh_failed": "auth", "ssh_accepted": "auth",
                               "fw_block": "firewall", "http_request": "web"}[kind])
    return Event(T0 + timedelta(seconds=seconds), source, kind, ip, raw=f"line@{seconds}", **kw)


@pytest.fixture
def sample_dir() -> Path:
    return ROOT / "sample_logs"
