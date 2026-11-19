"""Turn raw log lines into normalised ``Event`` objects.

Supported inputs
----------------
* ``auth``     - OpenSSH messages from /var/log/auth.log or /var/log/secure
* ``firewall`` - UFW / iptables kernel log lines (``SRC=... DPT=...``)
* ``web``      - Apache / Nginx "combined" access logs

Every value that comes out of a log line is attacker-controlled (usernames,
URL paths, user agents...), so the parsers never evaluate anything and the
report writers escape everything they print.
"""

from __future__ import annotations

import gzip
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Iterator, TextIO

SOURCES = ("auth", "firewall", "web")


@dataclass(frozen=True)
class Event:
    """One security-relevant line from a log file."""

    timestamp: datetime
    source: str  # "auth" | "firewall" | "web"
    kind: str  # e.g. "ssh_failed", "ssh_accepted", "fw_block", "http_request"
    src_ip: str
    user: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    raw: str = ""
    file: str = ""
    line_no: int = 0


@dataclass
class ParseStats:
    """Counters so the user can see how much of a file was understood."""

    lines: int = 0
    events: int = 0
    skipped: int = 0  # lines that are valid logs but not security-relevant, or malformed

    def add(self, other: "ParseStats") -> None:
        self.lines += other.lines
        self.events += other.events
        self.skipped += other.skipped


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def open_log(path: str | Path) -> TextIO:
    """Open a plain or gzip-compressed (rotated) log file as text."""
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _strip_tz(dt: datetime) -> datetime:
    # Timestamps are compared as written in the log (the server's local time).
    # Dropping the offset keeps syslog (no zone) and ISO/web (with zone) comparable.
    return dt.replace(tzinfo=None)


# Syslog header: classic BSD ("Nov 19 10:15:01") or RFC 3339 ("2026-11-19T10:15:01.123+05:30")
_SYSLOG_HEADER = re.compile(
    r"^(?:(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)


def _iter_syslog(
    lines: Iterable[str], year: int, stats: ParseStats
) -> Iterator[tuple[datetime, str, str, str, int]]:
    """Yield (timestamp, process, message, raw_line, line_no) for each syslog line.

    BSD syslog timestamps have no year. We start from ``year`` and roll over to
    the next year if the timestamps jump backwards by months (Dec -> Jan).
    """
    current_year = year
    last: datetime | None = None
    for line_no, raw in enumerate(lines, start=1):
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            continue
        stats.lines += 1
        m = _SYSLOG_HEADER.match(raw)
        if not m:
            stats.skipped += 1
            continue
        try:
            if m.group("iso"):
                ts = _strip_tz(datetime.fromisoformat(m.group("iso")))
            else:
                ts = datetime.strptime(f"{current_year} {m.group('bsd')}", "%Y %b %d %H:%M:%S")
                if last is not None and ts < last - timedelta(days=180):
                    current_year += 1
                    ts = ts.replace(year=current_year)
        except ValueError:
            stats.skipped += 1
            continue
        last = ts
        yield ts, m.group("proc"), m.group("msg"), raw, line_no


# --------------------------------------------------------------------------- #
# auth.log (OpenSSH)
# --------------------------------------------------------------------------- #

_SSH_METHODS = r"(?:password|publickey|keyboard-interactive/pam|hostbased)"
_SSH_FAILED = re.compile(
    rf"^Failed {_SSH_METHODS} for (?:invalid user )?(?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)
_SSH_ACCEPTED = re.compile(
    rf"^Accepted {_SSH_METHODS} for (?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)


def parse_auth(lines: Iterable[str], *, year: int, file: str = "", stats: ParseStats | None = None) -> Iterator[Event]:
    stats = stats if stats is not None else ParseStats()
    for ts, proc, msg, raw, line_no in _iter_syslog(lines, year, stats):
        if proc != "sshd":
            stats.skipped += 1
            continue
        for regex, kind in ((_SSH_FAILED, "ssh_failed"), (_SSH_ACCEPTED, "ssh_accepted")):
            m = regex.match(msg)
            if m and _valid_ip(m.group("ip")):
                stats.events += 1
                yield Event(ts, "auth", kind, m.group("ip"), user=m.group("user"),
                            raw=raw, file=file, line_no=line_no)
                break
        else:
            stats.skipped += 1


# --------------------------------------------------------------------------- #
# Firewall (UFW / iptables LOG target)
# --------------------------------------------------------------------------- #

_FW_FIELDS = re.compile(r"\b(SRC|DST|PROTO|DPT)=(\S+)")
_UFW_ACTION = re.compile(r"\[UFW (\w+)\]")


def parse_firewall(lines: Iterable[str], *, year: int, file: str = "", stats: ParseStats | None = None) -> Iterator[Event]:
    stats = stats if stats is not None else ParseStats()
    for ts, _proc, msg, raw, line_no in _iter_syslog(lines, year, stats):
        fields = dict(_FW_FIELDS.findall(msg))
        src, dpt = fields.get("SRC"), fields.get("DPT")
        if not src or not dpt or not dpt.isdigit() or not _valid_ip(src):
            stats.skipped += 1
            continue
        action = _UFW_ACTION.search(msg)
        kind = f"fw_{action.group(1).lower()}" if action else "fw_packet"
        stats.events += 1
        yield Event(ts, "firewall", kind, src, dst_port=int(dpt), protocol=fields.get("PROTO"),
                    raw=raw, file=file, line_no=line_no)


# --------------------------------------------------------------------------- #
# Web server access log (Apache / Nginx "combined" format)
# --------------------------------------------------------------------------- #

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) \S+'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_web(lines: Iterable[str], *, file: str = "", stats: ParseStats | None = None, **_: object) -> Iterator[Event]:
    stats = stats if stats is not None else ParseStats()
    for line_no, raw in enumerate(lines, start=1):
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            continue
        stats.lines += 1
        m = _COMBINED.match(raw)
        if not m or not _valid_ip(m.group("ip")):
            stats.skipped += 1
            continue
        try:
            ts = _strip_tz(datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z"))
        except ValueError:
            stats.skipped += 1
            continue
        parts = m.group("request").split()
        path = parts[1] if len(parts) >= 2 else (m.group("request") or "-")
        stats.events += 1
        yield Event(ts, "web", "http_request", m.group("ip"), path=path,
                    status=int(m.group("status")), user_agent=m.group("ua"),
                    raw=raw, file=file, line_no=line_no)


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #

_PARSERS = {"auth": parse_auth, "firewall": parse_firewall, "web": parse_web}


def parse_file(path: str | Path, source: str, *, year: int) -> tuple[list[Event], ParseStats]:
    """Parse one log file of the given ``source`` type."""
    if source not in _PARSERS:
        raise ValueError(f"unknown source {source!r}; expected one of {SOURCES}")
    stats = ParseStats()
    with open_log(path) as fh:
        events = list(_PARSERS[source](fh, year=year, file=str(path), stats=stats))
    return events, stats
