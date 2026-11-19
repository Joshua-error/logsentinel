"""Detection rules. Each rule turns a list of events into ATT&CK-tagged findings."""

from __future__ import annotations

import bisect
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Hashable, Iterable, Sequence

from .config import Config
from .parsers import Event

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_EVIDENCE = 6

# Tools that announce themselves in the User-Agent header.
KNOWN_SCANNER_AGENTS = (
    "nikto", "sqlmap", "gobuster", "dirbuster", "dirb", "feroxbuster", "ffuf",
    "wfuzz", "nuclei", "nmap", "masscan", "zgrab", "wpscan", "acunetix", "nessus",
)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


PASSWORD_GUESSING = Technique("T1110.001", "Brute Force: Password Guessing", "Credential Access")
VALID_ACCOUNTS = Technique("T1078", "Valid Accounts", "Initial Access")
NETWORK_SERVICE_DISCOVERY = Technique("T1046", "Network Service Discovery", "Discovery")
WORDLIST_SCANNING = Technique("T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    technique: Technique
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    description: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "technique_id": self.technique.id,
            "technique_name": self.technique.name,
            "tactic": self.technique.tactic,
            "technique_url": self.technique.url,
            "src_ip": self.src_ip,
            "first_seen": self.first_seen.isoformat(sep=" "),
            "last_seen": self.last_seen.isoformat(sep=" "),
            "count": self.count,
            "description": self.description,
            "evidence": list(self.evidence),
        }


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

def find_bursts(
    events: Sequence[Event],
    threshold: int,
    window: timedelta,
    key: Callable[[Event], Hashable] | None = None,
) -> list[list[Event]]:
    """Sliding-window burst detection over time-sorted events.

    A burst is any stretch where at least ``threshold`` events (or, if ``key``
    is given, ``threshold`` *distinct* key values) fall inside ``window``.
    Overlapping windows are merged so one attack produces one finding.
    Runs in O(n).
    """
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    counts: Counter = Counter()
    ranges: list[list[int]] = []
    left = 0
    for right, event in enumerate(events):
        counts[key(event) if key else right] += 1
        while event.timestamp - events[left].timestamp > window:
            old = key(events[left]) if key else left
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]
            left += 1
        if len(counts) >= threshold:
            if ranges and left <= ranges[-1][1]:
                ranges[-1][1] = right  # still the same attack: extend it
            else:
                ranges.append([left, right])
    return [list(events[a : b + 1]) for a, b in ranges]


def group_by_ip(events: Iterable[Event], predicate: Callable[[Event], bool]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if predicate(event):
            groups[event.src_ip].append(event)
    for group in groups.values():
        group.sort(key=lambda e: e.timestamp)
    return dict(groups)


def humanize(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _sample(values: Iterable[object], limit: int = 8) -> str:
    items = list(values)
    shown = ", ".join(str(v) for v in items[:limit])
    return shown + (f", +{len(items) - limit} more" if len(items) > limit else "")


def _evidence(events: Sequence[Event]) -> list[str]:
    if len(events) <= MAX_EVIDENCE:
        return [e.raw for e in events]
    half = MAX_EVIDENCE // 2
    return [e.raw for e in events[:half]] + ["..."] + [e.raw for e in events[-half:]]


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

def detect_ssh_brute_force(events: Sequence[Event], config: Config) -> list[Finding]:
    """LS-001: many failed SSH logins from one IP in a short window."""
    cfg = config.brute_force
    findings = []
    for ip, failures in group_by_ip(events, lambda e: e.kind == "ssh_failed").items():
        for burst in find_bursts(failures, cfg.threshold, timedelta(seconds=cfg.window_seconds)):
            users = Counter(e.user for e in burst)
            span = burst[-1].timestamp - burst[0].timestamp
            findings.append(Finding(
                rule_id="LS-001",
                title="SSH brute-force attempt",
                severity="medium",
                technique=PASSWORD_GUESSING,
                src_ip=ip,
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                count=len(burst),
                description=(
                    f"{len(burst)} failed SSH logins from {ip} in {humanize(span)} against "
                    f"{len(users)} account(s): {_sample(u for u, _ in users.most_common())}."
                ),
                evidence=_evidence(burst),
            ))
    return findings


def detect_success_after_failures(events: Sequence[Event], config: Config) -> list[Finding]:
    """LS-002: a successful SSH login from an IP that was just failing to log in."""
    cfg = config.success_after_failures
    lookback = timedelta(seconds=cfg.lookback_seconds)
    failures = group_by_ip(events, lambda e: e.kind == "ssh_failed")
    times = {ip: [e.timestamp for e in evs] for ip, evs in failures.items()}
    findings = []
    for success in sorted((e for e in events if e.kind == "ssh_accepted"), key=lambda e: e.timestamp):
        ip_times = times.get(success.src_ip)
        if not ip_times:
            continue
        lo = bisect.bisect_left(ip_times, success.timestamp - lookback)
        hi = bisect.bisect_right(ip_times, success.timestamp)
        recent = failures[success.src_ip][lo:hi]
        if len(recent) < cfg.min_failures:
            continue
        findings.append(Finding(
            rule_id="LS-002",
            title="Successful SSH login after repeated failures",
            severity="critical",
            technique=VALID_ACCOUNTS,
            src_ip=success.src_ip,
            first_seen=recent[0].timestamp,
            last_seen=success.timestamp,
            count=len(recent),
            description=(
                f"'{success.user}' logged in from {success.src_ip} after {len(recent)} failed "
                f"attempts in the preceding {humanize(success.timestamp - recent[0].timestamp)}. "
                f"Treat this account as possibly compromised."
            ),
            evidence=_evidence(recent + [success]),
        ))
    return findings


def detect_port_scan(events: Sequence[Event], config: Config) -> list[Finding]:
    """LS-003: one IP touching many different ports in a short window."""
    cfg = config.port_scan
    findings = []
    groups = group_by_ip(events, lambda e: e.source == "firewall" and e.dst_port is not None)
    for ip, packets in groups.items():
        for burst in find_bursts(packets, cfg.distinct_ports, timedelta(seconds=cfg.window_seconds),
                                 key=lambda e: e.dst_port):
            ports = sorted({e.dst_port for e in burst})
            protocols = sorted({e.protocol or "?" for e in burst})
            span = burst[-1].timestamp - burst[0].timestamp
            findings.append(Finding(
                rule_id="LS-003",
                title="Port scan",
                severity="medium",
                technique=NETWORK_SERVICE_DISCOVERY,
                src_ip=ip,
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                count=len(burst),
                description=(
                    f"{ip} probed {len(ports)} distinct {'/'.join(protocols)} ports in "
                    f"{humanize(span)}: {_sample(ports, 12)}."
                ),
                evidence=_evidence(burst),
            ))
    return findings


def detect_web_scan(events: Sequence[Event], config: Config) -> list[Finding]:
    """LS-004: one IP requesting many different missing/forbidden URLs (content discovery)."""
    cfg = config.web_scan
    statuses = set(cfg.statuses)
    findings = []
    groups = group_by_ip(events, lambda e: e.source == "web" and e.status in statuses)
    for ip, requests in groups.items():
        for burst in find_bursts(requests, cfg.distinct_paths, timedelta(seconds=cfg.window_seconds),
                                 key=lambda e: e.path):
            paths = list(dict.fromkeys(e.path for e in burst))
            agents = sorted({e.user_agent for e in burst if e.user_agent})
            tools = sorted({t for a in agents for t in KNOWN_SCANNER_AGENTS if t in a.lower()})
            span = burst[-1].timestamp - burst[0].timestamp
            description = (
                f"{ip} requested {len(paths)} distinct URLs that returned "
                f"{'/'.join(str(s) for s in sorted(statuses))} in {humanize(span)}: {_sample(paths, 6)}."
            )
            if tools:
                description += f" User-Agent identifies scanning tool(s): {', '.join(tools)}."
            findings.append(Finding(
                rule_id="LS-004",
                title="Web content discovery scan",
                severity="medium" if tools else "low",
                technique=WORDLIST_SCANNING,
                src_ip=ip,
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                count=len(burst),
                description=description,
                evidence=_evidence(burst),
            ))
    return findings


RULES = (detect_ssh_brute_force, detect_success_after_failures, detect_port_scan, detect_web_scan)


def is_allowlisted(ip: str, networks: Sequence) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks if addr.version == net.version)


def run_rules(events: Sequence[Event], config: Config) -> list[Finding]:
    """Run every rule and return findings, most severe first."""
    networks = config.allowlisted_networks()
    if networks:
        events = [e for e in events if not is_allowlisted(e.src_ip, networks)]
    findings = [f for rule in RULES for f in rule(events, config)]
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.first_seen, f.src_ip))
    return findings


def correlate_by_ip(findings: Sequence[Finding]) -> list[tuple[str, list[Finding]]]:
    """Source IPs that triggered more than one finding, with findings in time order.

    Read in order, these show an attacker's progress through the ATT&CK tactics,
    e.g. Discovery (port scan) -> Credential Access (brute force) -> Initial Access.
    """
    by_ip: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_ip[f.src_ip].append(f)
    chains = [(ip, sorted(fs, key=lambda f: (f.first_seen, f.last_seen)))
              for ip, fs in by_ip.items() if len(fs) > 1]
    chains.sort(key=lambda c: (-max(SEVERITY_ORDER[f.severity] for f in c[1]), c[1][0].first_seen))
    return chains
