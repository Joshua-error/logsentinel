"""Generate realistic, fully synthetic sample logs for demos and tests.

The day (18 Nov) contains normal activity plus four planted attack scenarios:

  02:10  203.0.113.45   port scan (UFW)                      -> LS-003
  02:14  203.0.113.45   SSH brute force against many users   -> LS-001
  03:41  198.51.100.23  SSH brute force on 'deploy' ...      -> LS-001
  03:44  198.51.100.23  ... followed by a successful login   -> LS-002
  05:00  203.0.113.77   slow brute force, 1 try / ~12 min    -> NOT detected (documented limitation)
  11:22  198.51.100.99  gobuster directory scan (web)        -> LS-004

All IPs come from the RFC 5737 documentation ranges, so nothing here points at
a real host. Output is deterministic (fixed random seed).

Usage:  python scripts/generate_sample_logs.py [output_dir]
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web-01"
DAY = datetime(2026, 11, 18)
SERVER_IP = "10.0.0.5"
rng = random.Random(42)


def syslog_ts(dt: datetime) -> str:
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S}"


def at(hh: int, mm: int, ss: int = 0) -> datetime:
    return DAY.replace(hour=hh, minute=mm, second=ss)


def pid() -> int:
    return rng.randint(1000, 65000)


# --------------------------------------------------------------------------- #
# auth.log
# --------------------------------------------------------------------------- #

def auth_lines() -> list[tuple[datetime, str]]:
    out: list[tuple[datetime, str]] = []

    def sshd(dt: datetime, msg: str, p: int | None = None) -> None:
        out.append((dt, f"{syslog_ts(dt)} {HOST} sshd[{p or pid()}]: {msg}"))

    def other(dt: datetime, proc: str, msg: str) -> None:
        out.append((dt, f"{syslog_ts(dt)} {HOST} {proc}: {msg}"))

    # Background noise: hourly cron
    for hour in range(24):
        dt = at(hour, 17, 1)
        other(dt, f"CRON[{pid()}]", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        other(dt + timedelta(seconds=1), f"CRON[{pid()}]", "pam_unix(cron:session): session closed for user root")

    # Normal admin logins (key-based)
    for dt in (at(8, 2, 11), at(13, 30, 45), at(18, 45, 3)):
        p = pid()
        sshd(dt, f"Accepted publickey for alice from 192.0.2.10 port {rng.randint(40000, 60000)} ssh2: "
                 "ED25519 SHA256:q1w2e3r4t5y6u7i8o9p0", p)
        sshd(dt, "pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)", p)
    other(at(8, 5, 2), "sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")

    # A legitimate user mistyping their password twice (must NOT alert)
    for dt in (at(9, 15, 2), at(9, 15, 9)):
        sshd(dt, f"Failed password for bob from 192.0.2.11 port {rng.randint(40000, 60000)} ssh2")
    sshd(at(9, 15, 20), f"Accepted password for bob from 192.0.2.11 port {rng.randint(40000, 60000)} ssh2")

    # Scenario A: fast brute force over many usernames
    users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "pi", "user", "git"]
    dt = at(2, 14, 3)
    for i in range(48):
        user = users[i % len(users)]
        port = rng.randint(30000, 65000)
        p = pid()
        if user == "root":
            sshd(dt, f"Failed password for root from 203.0.113.45 port {port} ssh2", p)
        else:
            sshd(dt, f"Invalid user {user} from 203.0.113.45 port {port}", p)
            sshd(dt, f"Failed password for invalid user {user} from 203.0.113.45 port {port} ssh2", p)
        dt += timedelta(seconds=rng.randint(2, 5))

    # Scenario B: targeted brute force that succeeds
    dt = at(3, 41, 10)
    for _ in range(30):
        sshd(dt, f"Failed password for deploy from 198.51.100.23 port {rng.randint(30000, 65000)} ssh2")
        dt += timedelta(seconds=rng.randint(4, 9))
    p = pid()
    sshd(dt, f"Accepted password for deploy from 198.51.100.23 port {rng.randint(30000, 65000)} ssh2", p)
    sshd(dt, "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)", p)

    # Scenario C: low-and-slow brute force (below the rate threshold on purpose)
    dt = at(5, 0, 30)
    for _ in range(8):
        sshd(dt, f"Failed password for root from 203.0.113.77 port {rng.randint(30000, 65000)} ssh2")
        dt += timedelta(minutes=rng.randint(11, 14))

    return out


# --------------------------------------------------------------------------- #
# ufw.log
# --------------------------------------------------------------------------- #

def ufw_line(dt: datetime, src: str, dpt: int, proto: str = "TCP") -> tuple[datetime, str]:
    uptime = (dt - DAY).total_seconds() + 86400 * 3
    return dt, (
        f"{syslog_ts(dt)} {HOST} kernel: [{uptime:.6f}] [UFW BLOCK] IN=eth0 OUT= "
        f"MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 SRC={src} DST={SERVER_IP} LEN=44 TOS=0x00 "
        f"PREC=0x00 TTL={rng.randint(40, 60)} ID={rng.randint(1, 65535)} PROTO={proto} "
        f"SPT={rng.randint(30000, 65000)} DPT={dpt} WINDOW=1024 RES=0x00 SYN URGP=0"
    )


def firewall_lines() -> list[tuple[datetime, str]]:
    out = []
    # Internet background noise: random hosts poking 1-3 common ports
    for _ in range(40):
        src = f"198.51.100.{rng.randint(100, 250)}"
        dt = at(rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
        for port in rng.sample([23, 445, 3389, 8080, 5900, 1433], k=rng.randint(1, 3)):
            out.append(ufw_line(dt, src, port))
            dt += timedelta(seconds=rng.randint(1, 30))

    # Scenario A, step 1: SYN scan of 60 ports from the future brute-forcer
    common = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
              1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
    ports = common + rng.sample([p for p in range(1, 10000) if p not in common], 34)
    rng.shuffle(ports)
    dt = at(2, 10, 0)
    for i, port in enumerate(ports):
        out.append(ufw_line(dt, "203.0.113.45", port))
        if i % 4 == 3:
            dt += timedelta(seconds=1)
    return out


# --------------------------------------------------------------------------- #
# access.log
# --------------------------------------------------------------------------- #

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36",
]


def access_line(dt: datetime, ip: str, path: str, status: int, ua: str, method: str = "GET") -> tuple[datetime, str]:
    size = rng.randint(200, 9000) if status == 200 else rng.randint(150, 400)
    return dt, (f'{ip} - - [{dt:%d/%b/%Y:%H:%M:%S} +0530] "{method} {path} HTTP/1.1" {status} {size} '
                f'"-" "{ua}"')


def web_lines() -> list[tuple[datetime, str]]:
    out = []
    pages = ["/", "/about", "/blog/", "/blog/hello-world", "/contact",
             "/static/css/site.css", "/static/js/app.js", "/favicon.ico"]
    visitors = [f"192.0.2.{n}" for n in range(20, 36)]
    for _ in range(320):
        dt = at(rng.randint(6, 23), rng.randint(0, 59), rng.randint(0, 59))
        out.append(access_line(dt, rng.choice(visitors), rng.choice(pages), 200, rng.choice(BROWSERS)))
    # A real visitor hitting a couple of broken links (must NOT alert)
    for i, path in enumerate(["/blog/old-post", "/favicon.png", "/blog/old-post"]):
        out.append(access_line(at(14, 2, 10 + i * 4), "192.0.2.27", path, 404, BROWSERS[0]))

    # Scenario D: directory brute force with gobuster
    wordlist = ["/admin", "/administrator", "/login", "/wp-login.php", "/wp-admin/", "/.env", "/.git/config",
                "/backup.zip", "/backup.sql", "/db.sql", "/config.php", "/phpmyadmin/", "/server-status",
                "/.htaccess", "/robots.txt", "/api/", "/api/v1/users", "/console", "/debug", "/test",
                "/old", "/dev", "/uploads/", "/shell.php", "/cgi-bin/", "/xmlrpc.php", "/.DS_Store",
                "/web.config", "/actuator/health", "/.aws/credentials", "/id_rsa", "/dump.sql",
                "/admin.php", "/manager/html", "/setup.php", "/install.php", "/info.php", "/staging",
                "/private/", "/secret"]
    dt = at(11, 22, 4)
    for path in wordlist:
        status = 200 if path == "/robots.txt" else 403 if path in ("/admin", "/server-status") else 404
        out.append(access_line(dt, "198.51.100.99", path, status, "gobuster/3.6"))
        dt += timedelta(seconds=rng.choice([0, 0, 1]))
    return out


def write(path: Path, lines: list[tuple[datetime, str]]) -> None:
    lines.sort(key=lambda item: item[0])  # stable: keeps same-second order
    path.write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(lines)} lines)")


def main() -> None:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "sample_logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    write(out_dir / "auth.log", auth_lines())
    write(out_dir / "ufw.log", firewall_lines())
    write(out_dir / "access.log", web_lines())


if __name__ == "__main__":
    main()
