from datetime import timedelta

import pytest

from conftest import ev
from logsentinel.config import Config
from logsentinel.rules import (
    correlate_by_ip,
    detect_port_scan,
    detect_ssh_brute_force,
    detect_success_after_failures,
    detect_web_scan,
    find_bursts,
    run_rules,
)


# --- find_bursts ------------------------------------------------------------ #

def test_bursts_merge_overlapping_windows():
    events = [ev(i) for i in range(20)]  # 20 events, one per second
    bursts = find_bursts(events, threshold=5, window=timedelta(seconds=10))
    assert len(bursts) == 1 and len(bursts[0]) == 20


def test_bursts_split_separate_attacks():
    events = [ev(i) for i in range(5)] + [ev(3600 + i) for i in range(5)]
    assert len(find_bursts(events, 5, timedelta(seconds=60))) == 2


def test_bursts_distinct_key():
    same_port = [ev(i, "fw_block", dst_port=22) for i in range(50)]
    assert find_bursts(same_port, 10, timedelta(seconds=60), key=lambda e: e.dst_port) == []


def test_bursts_rejects_bad_threshold():
    with pytest.raises(ValueError):
        find_bursts([], 0, timedelta(seconds=1))


# --- LS-001 brute force ----------------------------------------------------- #

def test_brute_force_triggers_at_threshold():
    events = [ev(i * 5, user=u) for i, u in enumerate(["root", "admin", "root", "pi", "test"])]
    [f] = detect_ssh_brute_force(events, Config())
    assert f.rule_id == "LS-001" and f.technique.id == "T1110.001" and f.count == 5
    assert "4 account(s)" in f.description


def test_brute_force_below_threshold_is_quiet():
    events = [ev(i * 5, user="root") for i in range(4)]
    assert detect_ssh_brute_force(events, Config()) == []


def test_brute_force_slow_attack_is_not_detected():
    # Documented limitation: 1 attempt every 2 minutes stays under the rate rule.
    events = [ev(i * 120, user="root") for i in range(30)]
    assert detect_ssh_brute_force(events, Config()) == []


def test_brute_force_is_per_ip():
    events = [ev(i, ip=f"192.0.2.{i}", user="root") for i in range(10)]
    assert detect_ssh_brute_force(events, Config()) == []


# --- LS-002 success after failures ------------------------------------------ #

def test_success_after_failures():
    events = [ev(i * 10, user="deploy") for i in range(6)] + [ev(70, "ssh_accepted", user="deploy")]
    [f] = detect_success_after_failures(events, Config())
    assert f.severity == "critical" and f.technique.id == "T1078" and f.count == 6
    assert "'deploy'" in f.description and f.evidence[-1] == "line@70"


def test_success_after_few_failures_is_quiet():
    events = [ev(0, user="bob"), ev(5, user="bob"), ev(10, "ssh_accepted", user="bob")]
    assert detect_success_after_failures(events, Config()) == []


def test_success_long_after_failures_is_quiet():
    events = [ev(i, user="deploy") for i in range(10)] + [ev(3600, "ssh_accepted", user="deploy")]
    assert detect_success_after_failures(events, Config()) == []


def test_success_from_different_ip_is_quiet():
    events = [ev(i, user="deploy") for i in range(10)] + [ev(20, "ssh_accepted", ip="192.0.2.10", user="deploy")]
    assert detect_success_after_failures(events, Config()) == []


# --- LS-003 port scan -------------------------------------------------------- #

def test_port_scan():
    events = [ev(i * 0.5, "fw_block", dst_port=port, protocol="TCP") for i, port in enumerate(range(20, 40))]
    [f] = detect_port_scan(events, Config())
    assert f.technique.id == "T1046" and "20 distinct TCP ports" in f.description


def test_port_scan_needs_distinct_ports():
    events = [ev(i, "fw_block", dst_port=22 + (i % 3)) for i in range(100)]
    assert detect_port_scan(events, Config()) == []


# --- LS-004 web scan --------------------------------------------------------- #

def test_web_scan_with_known_tool_is_medium():
    events = [ev(i, "http_request", path=f"/p{i}", status=404, user_agent="gobuster/3.6") for i in range(20)]
    [f] = detect_web_scan(events, Config())
    assert f.technique.id == "T1595.003" and f.severity == "medium" and "gobuster" in f.description


def test_web_scan_without_tool_name_is_low():
    events = [ev(i, "http_request", path=f"/p{i}", status=404, user_agent="Mozilla/5.0") for i in range(20)]
    [f] = detect_web_scan(events, Config())
    assert f.severity == "low"


def test_web_scan_ignores_successful_requests():
    events = [ev(i, "http_request", path=f"/p{i}", status=200) for i in range(50)]
    assert detect_web_scan(events, Config()) == []


# --- engine ------------------------------------------------------------------ #

def test_allowlist_cidr_suppresses_findings():
    events = [ev(i, user="root", ip="10.1.2.3") for i in range(10)]
    config = Config(allowlist=["10.0.0.0/8"])
    assert run_rules(events, config) == []
    assert len(run_rules(events, Config())) == 1


def test_findings_sorted_by_severity_and_chained():
    ip = "198.51.100.23"
    events = [ev(i * 5, ip=ip, user="deploy") for i in range(8)] + [ev(45, "ssh_accepted", ip=ip, user="deploy")]
    findings = run_rules(events, Config())
    assert [f.rule_id for f in findings] == ["LS-002", "LS-001"]
    [(chain_ip, chain)] = correlate_by_ip(findings)
    assert chain_ip == ip and [f.rule_id for f in chain] == ["LS-001", "LS-002"]
