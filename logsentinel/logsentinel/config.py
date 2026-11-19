"""Detection thresholds, loaded from an optional TOML file."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path


class ConfigError(ValueError):
    """Raised when the config file is malformed or has invalid values."""


@dataclass
class BruteForceConfig:
    threshold: int = 5          # failed logins from one IP ...
    window_seconds: int = 60    # ... within this many seconds


@dataclass
class SuccessAfterFailuresConfig:
    min_failures: int = 3       # failures from the same IP ...
    lookback_seconds: int = 600 # ... in this window before a successful login


@dataclass
class PortScanConfig:
    distinct_ports: int = 10    # distinct destination ports from one IP ...
    window_seconds: int = 60    # ... within this many seconds


@dataclass
class WebScanConfig:
    distinct_paths: int = 15    # distinct URLs returning an error status ...
    window_seconds: int = 120   # ... within this many seconds
    statuses: list[int] = field(default_factory=lambda: [401, 403, 404])


@dataclass
class Config:
    allowlist: list[str] = field(default_factory=list)  # IPs / CIDRs never alerted on
    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    success_after_failures: SuccessAfterFailuresConfig = field(default_factory=SuccessAfterFailuresConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    web_scan: WebScanConfig = field(default_factory=WebScanConfig)

    def allowlisted_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(entry, strict=False) for entry in self.allowlist]


def _apply(obj: object, data: dict, where: str) -> None:
    known = {f.name for f in fields(obj)}
    for key, value in data.items():
        name = f"{where}{key}"
        if key not in known:
            raise ConfigError(f"unknown setting '{name}'")
        current = getattr(obj, key)
        if is_dataclass(current):
            if not isinstance(value, dict):
                raise ConfigError(f"'{name}' must be a [table]")
            _apply(current, value, f"{name}.")
        elif isinstance(current, list):
            if not isinstance(value, list):
                raise ConfigError(f"'{name}' must be a list")
            setattr(obj, key, value)
        elif isinstance(current, int):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigError(f"'{name}' must be a positive integer")
            setattr(obj, key, value)


def load_config(path: str | Path | None = None) -> Config:
    """Return the default config, overridden by values from ``path`` if given."""
    config = Config()
    if path is None:
        return config
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    _apply(config, data, "")
    try:
        config.allowlisted_networks()
    except ValueError as exc:
        raise ConfigError(f"invalid allowlist entry: {exc}") from exc
    if not all(isinstance(s, int) for s in config.web_scan.statuses):
        raise ConfigError("'web_scan.statuses' must be a list of HTTP status codes")
    return config
