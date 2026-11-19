"""Write findings as CSV, JSON, HTML and a console summary.

Log content is attacker-controlled, so:
* HTML output escapes every value (prevents stored XSS in the report), and
* CSV output neutralises cells starting with = + - @ (prevents formula
  injection when an analyst opens the file in Excel / Sheets).
"""

from __future__ import annotations

import csv
import html
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Sequence, TextIO

from . import __version__
from .parsers import ParseStats
from .rules import SEVERITY_ORDER, Finding, correlate_by_ip

CSV_FIELDS = [
    "severity", "rule_id", "title", "technique_id", "technique_name", "tactic",
    "src_ip", "first_seen", "last_seen", "count", "description",
]


def csv_safe(value: object) -> object:
    """Prefix spreadsheet formula triggers so they are shown as text, not executed."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_csv(findings: Sequence[Finding], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            writer.writerow({k: csv_safe(v) for k, v in f.to_dict().items()})


def write_json(findings: Sequence[Finding], path: Path, *, inputs: Sequence[str], stats: ParseStats) -> None:
    payload = {
        "tool": "logsentinel",
        "version": __version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "inputs": list(inputs),
        "stats": {"lines": stats.lines, "events": stats.events, "skipped": stats.skipped},
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--muted:#5d6577;--line:#e3e6ec;
--critical:#b42318;--high:#d9480f;--medium:#b7791f;--low:#2f6fb3}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
background:var(--bg);color:var(--ink)}header{background:#141a26;color:#fff;padding:28px 40px}
header h1{margin:0;font-size:24px}header p{margin:4px 0 0;color:#aab3c5}main{max-width:1200px;margin:0 auto;padding:28px 40px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:28px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card .n{font-size:28px;font-weight:700}.card .l{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.04em}
h2{font-size:18px;margin:32px 0 12px}table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:10px;overflow:hidden}th,td{text-align:left;padding:10px 12px;
border-bottom:1px solid var(--line);vertical-align:top}th{background:#eef0f4;font-size:12px;text-transform:uppercase;
letter-spacing:.04em;color:var(--muted)}tr:last-child td{border-bottom:0}
.sev{display:inline-block;padding:2px 9px;border-radius:999px;color:#fff;font-size:12px;font-weight:600;text-transform:uppercase}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
pre{background:#141a26;color:#d7dde8;padding:10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
details summary{cursor:pointer;color:var(--muted);font-size:13px}a{color:#2f6fb3}
.chain{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:10px}
.chain .steps{color:var(--muted)}.empty{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px}
footer{color:var(--muted);font-size:13px;padding:10px 40px 40px;max-width:1200px;margin:0 auto}
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_html(findings: Sequence[Finding], *, inputs: Sequence[str], stats: ParseStats) -> str:
    by_sev = Counter(f.severity for f in findings)
    cards = [("Findings", len(findings)), ("Unique source IPs", len({f.src_ip for f in findings}))]
    cards += [(sev.title(), by_sev.get(sev, 0)) for sev in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)]
    card_html = "".join(f'<div class="card"><div class="n">{_e(n)}</div><div class="l">{_e(label)}</div></div>'
                        for label, n in cards)

    chains = correlate_by_ip(findings)
    chain_html = ""
    if chains:
        items = []
        for ip, fs in chains:
            steps = " &rarr; ".join(f"{_e(f.technique.tactic)} ({_e(f.technique.id)})" for f in fs)
            items.append(f'<div class="chain"><strong><code>{_e(ip)}</code></strong> '
                         f'&mdash; {len(fs)} findings<div class="steps">{steps}</div></div>')
        chain_html = "<h2>Attack chains (same source, multiple findings)</h2>" + "".join(items)

    if findings:
        rows = []
        for f in findings:
            evidence = "\n".join(f.evidence)
            rows.append(
                "<tr>"
                f'<td><span class="sev {_e(f.severity)}">{_e(f.severity)}</span></td>'
                f"<td><strong>{_e(f.title)}</strong><br><code>{_e(f.rule_id)}</code></td>"
                f'<td><a href="{_e(f.technique.url)}" target="_blank" rel="noopener">{_e(f.technique.id)}</a>'
                f"<br>{_e(f.technique.name)}<br><small>{_e(f.technique.tactic)}</small></td>"
                f"<td><code>{_e(f.src_ip)}</code></td>"
                f"<td>{_e(f.first_seen.isoformat(sep=' '))}<br>{_e(f.last_seen.isoformat(sep=' '))}</td>"
                f"<td>{_e(f.count)}</td>"
                f"<td>{_e(f.description)}<details><summary>Evidence ({len(f.evidence)} lines)</summary>"
                f"<pre>{_e(evidence)}</pre></details></td>"
                "</tr>"
            )
        table = ("<table><thead><tr><th>Severity</th><th>Finding</th><th>MITRE ATT&amp;CK</th><th>Source</th>"
                 "<th>First / last seen</th><th>Events</th><th>Details</th></tr></thead><tbody>"
                 + "".join(rows) + "</tbody></table>")
    else:
        table = '<div class="empty">No suspicious activity detected with the current thresholds.</div>'

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    input_list = ", ".join(f"<code>{_e(p)}</code>" for p in inputs)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogSentinel report</title><style>{_CSS}</style></head>
<body><header><h1>LogSentinel report</h1><p>Generated {_e(generated)} &middot; LogSentinel v{_e(__version__)}</p></header>
<main><div class="cards">{card_html}</div>{chain_html}<h2>Findings</h2>{table}</main>
<footer>Inputs: {input_list}<br>{stats.events} security events from {stats.lines} lines
({stats.skipped} lines not security-relevant or unparsed).</footer></body></html>
"""


def write_html(findings: Sequence[Finding], path: Path, *, inputs: Sequence[str], stats: ParseStats) -> None:
    path.write_text(render_html(findings, inputs=inputs, stats=stats), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #

def print_summary(findings: Sequence[Finding], stats: ParseStats, out: TextIO | None = None) -> None:
    out = out or sys.stdout  # resolved at call time so redirection/capture works
    print(f"Parsed {stats.lines} lines -> {stats.events} security events "
          f"({stats.skipped} skipped)", file=out)
    if not findings:
        print("No suspicious activity detected.", file=out)
        return
    print(f"\n{len(findings)} finding(s):\n", file=out)
    print(f"  {'SEVERITY':<9} {'RULE':<7} {'ATT&CK':<10} {'SOURCE IP':<16} {'FIRST SEEN':<20} TITLE", file=out)
    for f in findings:
        print(f"  {f.severity.upper():<9} {f.rule_id:<7} {f.technique.id:<10} {f.src_ip:<16} "
              f"{f.first_seen.isoformat(sep=' '):<20} {f.title}", file=out)
    chains = correlate_by_ip(findings)
    if chains:
        print("\nAttack chains:", file=out)
        for ip, fs in chains:
            print(f"  {ip}: " + " -> ".join(f"{f.technique.tactic} ({f.technique.id})" for f in fs), file=out)
