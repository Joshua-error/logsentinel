"""Command-line interface: ``logsentinel --auth auth.log --firewall ufw.log --web access.log``."""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .parsers import ParseStats, parse_file
from .report import print_summary, write_csv, write_html, write_json
from .rules import run_rules

FORMATS = ("csv", "json", "html")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentinel",
        description="Detect brute force, scanning and suspicious logins in Linux and web "
                    "server logs, with every finding mapped to MITRE ATT&CK.",
    )
    p.add_argument("--auth", action="append", default=[], type=Path, metavar="PATH",
                   help="SSH auth log, e.g. /var/log/auth.log (repeatable, .gz supported)")
    p.add_argument("--firewall", action="append", default=[], type=Path, metavar="PATH",
                   help="UFW/iptables kernel log, e.g. /var/log/ufw.log (repeatable)")
    p.add_argument("--web", action="append", default=[], type=Path, metavar="PATH",
                   help="Apache/Nginx combined access log (repeatable)")
    p.add_argument("-c", "--config", type=Path, help="TOML file overriding detection thresholds")
    p.add_argument("--year", type=int, default=date.today().year,
                   help="year for syslog timestamps that omit it (default: current year)")
    p.add_argument("-o", "--out", type=Path, default=Path("reports"),
                   help="output directory for reports (default: ./reports)")
    p.add_argument("-f", "--format", default="csv,json,html",
                   help="comma-separated report formats: csv,json,html (default: all)")
    p.add_argument("-q", "--quiet", action="store_true", help="don't print the console summary")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    inputs = [(path, "auth") for path in args.auth]
    inputs += [(path, "firewall") for path in args.firewall]
    inputs += [(path, "web") for path in args.web]
    if not inputs:
        parser.error("give at least one log file with --auth, --firewall or --web")

    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    unknown = sorted(set(formats) - set(FORMATS))
    if unknown or not formats:
        parser.error(f"unknown format(s): {', '.join(unknown) or '(none)'}; choose from {', '.join(FORMATS)}")

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"logsentinel: config error: {exc}", file=sys.stderr)
        return 2

    events, stats = [], ParseStats()
    for path, source in inputs:
        if not path.is_file():
            print(f"logsentinel: file not found: {path}", file=sys.stderr)
            return 2
        file_events, file_stats = parse_file(path, source, year=args.year)
        events.extend(file_events)
        stats.add(file_stats)

    findings = run_rules(events, config)

    args.out.mkdir(parents=True, exist_ok=True)
    names = [str(p) for p, _ in inputs]
    written = []
    if "csv" in formats:
        write_csv(findings, args.out / "findings.csv")
        written.append(args.out / "findings.csv")
    if "json" in formats:
        write_json(findings, args.out / "findings.json", inputs=names, stats=stats)
        written.append(args.out / "findings.json")
    if "html" in formats:
        write_html(findings, args.out / "report.html", inputs=names, stats=stats)
        written.append(args.out / "report.html")

    if not args.quiet:
        print_summary(findings, stats)
        print("\nReports written: " + ", ".join(str(p) for p in written))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
