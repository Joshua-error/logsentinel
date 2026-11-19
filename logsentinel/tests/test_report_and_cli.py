import csv
import json

import pytest

from conftest import ev
from logsentinel.cli import main
from logsentinel.config import Config, ConfigError, load_config
from logsentinel.parsers import ParseStats
from logsentinel.report import csv_safe, render_html, write_csv
from logsentinel.rules import run_rules

# --- report safety ----------------------------------------------------------- #

def _malicious_findings():
    events = [ev(i, user="<script>alert(1)</script>") for i in range(6)]
    return run_rules(events, Config())


def test_html_escapes_attacker_controlled_values():
    page = render_html(_malicious_findings(), inputs=["auth.log"], stats=ParseStats())
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


@pytest.mark.parametrize("value", ["=cmd|' /C calc'!A0", "+1+1", "-2", "@SUM(A1)"])
def test_csv_formula_injection_is_neutralised(value):
    assert csv_safe(value) == "'" + value


def test_csv_written(tmp_path):
    path = tmp_path / "f.csv"
    write_csv(_malicious_findings(), path)
    rows = list(csv.DictReader(path.open()))
    assert rows[0]["technique_id"] == "T1110.001"


# --- config ------------------------------------------------------------------ #

def test_config_overrides(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text('allowlist = ["192.0.2.0/24"]\n[brute_force]\nthreshold = 20\n')
    config = load_config(path)
    assert config.brute_force.threshold == 20 and config.brute_force.window_seconds == 60


@pytest.mark.parametrize("text", [
    "[brute_force]\nthreshhold = 3\n",          # typo
    "[brute_force]\nthreshold = -1\n",          # not positive
    'allowlist = ["not-an-ip"]\n',              # bad CIDR
    "[brute_force\n",                           # invalid TOML
])
def test_config_errors(tmp_path, text):
    path = tmp_path / "c.toml"
    path.write_text(text)
    with pytest.raises(ConfigError):
        load_config(path)


# --- end to end on the bundled sample logs ----------------------------------- #

EXPECTED = {
    ("LS-001", "203.0.113.45"),   # fast SSH brute force
    ("LS-001", "198.51.100.23"),  # targeted brute force ...
    ("LS-002", "198.51.100.23"),  # ... that succeeded
    ("LS-003", "203.0.113.45"),   # port scan before the brute force
    ("LS-004", "198.51.100.99"),  # gobuster directory scan
}


def test_end_to_end_sample_logs(sample_dir, tmp_path, capsys):
    code = main([
        "--auth", str(sample_dir / "auth.log"),
        "--firewall", str(sample_dir / "ufw.log"),
        "--web", str(sample_dir / "access.log"),
        "--year", "2026", "--out", str(tmp_path),
    ])
    assert code == 0
    data = json.loads((tmp_path / "findings.json").read_text())
    found = {(f["rule_id"], f["src_ip"]) for f in data["findings"]}
    assert found == EXPECTED
    # benign activity and the low-and-slow attacker must not alert
    assert not {"192.0.2.11", "192.0.2.27", "203.0.113.77"} & {ip for _, ip in found}
    assert (tmp_path / "report.html").exists() and (tmp_path / "findings.csv").exists()
    assert "Attack chains" in capsys.readouterr().out


def test_cli_requires_input(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_cli_missing_file(tmp_path, capsys):
    assert main(["--auth", str(tmp_path / "nope.log"), "-o", str(tmp_path)]) == 2
    assert "file not found" in capsys.readouterr().err


def test_cli_single_format(sample_dir, tmp_path):
    assert main(["--web", str(sample_dir / "access.log"), "-f", "json", "-q", "-o", str(tmp_path)]) == 0
    assert [p.name for p in tmp_path.iterdir()] == ["findings.json"]
