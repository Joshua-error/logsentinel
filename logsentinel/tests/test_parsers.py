import gzip
from datetime import datetime

from logsentinel.parsers import ParseStats, parse_auth, parse_file, parse_firewall, parse_web


def test_auth_failed_invalid_user():
    line = "Nov 18 02:14:03 web-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 52314 ssh2"
    [e] = list(parse_auth([line], year=2026))
    assert (e.kind, e.user, e.src_ip) == ("ssh_failed", "admin", "203.0.113.45")
    assert e.timestamp == datetime(2026, 11, 18, 2, 14, 3)


def test_auth_accepted_publickey_and_ipv6():
    line = "Nov  5 08:02:11 web-01 sshd[99]: Accepted publickey for alice from 2001:db8::7 port 50000 ssh2: ED25519 SHA256:x"
    [e] = list(parse_auth([line], year=2026))
    assert (e.kind, e.user, e.src_ip) == ("ssh_accepted", "alice", "2001:db8::7")
    assert e.timestamp.day == 5


def test_auth_iso_timestamp():
    line = "2026-11-18T02:14:03.123456+05:30 web-01 sshd[1]: Failed password for root from 192.0.2.9 port 1 ssh2"
    [e] = list(parse_auth([line], year=1999))
    assert e.timestamp == datetime(2026, 11, 18, 2, 14, 3, 123456)


def test_auth_username_with_spaces_is_kept_verbatim():
    line = "Nov 18 02:14:03 h sshd[1]: Failed password for invalid user <script>x y</script> from 192.0.2.9 port 1 ssh2"
    [e] = list(parse_auth([line], year=2026))
    assert e.user == "<script>x y</script>"


def test_auth_ignores_unrelated_and_garbage_lines():
    lines = [
        "Nov 18 00:17:01 h CRON[1]: pam_unix(cron:session): session opened for user root",
        "Nov 18 02:14:03 h sshd[1]: Invalid user admin from 203.0.113.45 port 52314",
        "this is not a log line",
        "",
    ]
    stats = ParseStats()
    assert list(parse_auth(lines, year=2026, stats=stats)) == []
    assert (stats.lines, stats.events, stats.skipped) == (3, 0, 3)


def test_auth_rejects_invalid_ip():
    line = "Nov 18 02:14:03 h sshd[1]: Failed password for root from 999.1.1.1 port 1 ssh2"
    assert list(parse_auth([line], year=2026)) == []


def test_year_rolls_over_from_december_to_january():
    lines = [
        "Dec 31 23:59:58 h sshd[1]: Failed password for root from 192.0.2.9 port 1 ssh2",
        "Jan  1 00:00:02 h sshd[1]: Failed password for root from 192.0.2.9 port 1 ssh2",
    ]
    a, b = parse_auth(lines, year=2025)
    assert a.timestamp.year == 2025 and b.timestamp.year == 2026
    assert (b.timestamp - a.timestamp).total_seconds() == 4


def test_firewall_ufw_block():
    line = ("Nov 18 02:10:00 web-01 kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.45 "
            "DST=10.0.0.5 LEN=44 PROTO=TCP SPT=40000 DPT=3389 WINDOW=1024 SYN URGP=0")
    [e] = list(parse_firewall([line], year=2026))
    assert (e.kind, e.src_ip, e.dst_port, e.protocol) == ("fw_block", "203.0.113.45", 3389, "TCP")


def test_firewall_skips_lines_without_port():
    line = "Nov 18 02:10:00 web-01 kernel: [1.0] [UFW BLOCK] IN=eth0 SRC=203.0.113.45 DST=10.0.0.5 PROTO=ICMP TYPE=8"
    assert list(parse_firewall([line], year=2026)) == []


def test_web_combined_line():
    line = ('198.51.100.99 - - [18/Nov/2026:11:22:04 +0530] "GET /.env HTTP/1.1" 404 162 "-" "gobuster/3.6"')
    [e] = list(parse_web([line]))
    assert (e.src_ip, e.path, e.status, e.user_agent) == ("198.51.100.99", "/.env", 404, "gobuster/3.6")
    assert e.timestamp == datetime(2026, 11, 18, 11, 22, 4)


def test_web_malformed_request_line():
    line = '198.51.100.99 - - [18/Nov/2026:11:22:04 +0530] "-" 400 0 "-" "-"'
    [e] = list(parse_web([line]))
    assert e.path == "-" and e.status == 400


def test_parse_file_reads_gzip(tmp_path):
    path = tmp_path / "auth.log.1.gz"
    with gzip.open(path, "wt") as fh:
        fh.write("Nov 18 02:14:03 h sshd[1]: Failed password for root from 192.0.2.9 port 1 ssh2\n")
    events, stats = parse_file(path, "auth", year=2026)
    assert len(events) == 1 and stats.events == 1
