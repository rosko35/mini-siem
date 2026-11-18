"""Configuration: a YAML file for behaviour, environment variables for secrets.

Relative paths in the YAML file are resolved against the file's directory.
Environment overrides (handy in Docker):

    SIEM_CONFIG          path of the YAML file (default: ./config.yml)
    SIEM_DB              database path
    SIEM_DASHBOARD_HOST  dashboard bind address
    SIEM_DASHBOARD_PORT  dashboard port

Secrets are only ever read from the environment / .env:

    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    SIEM_DASHBOARD_TOKEN, SIEM_DASHBOARD_USER, SIEM_DASHBOARD_PASSWORD
"""

from __future__ import annotations

import os
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceConfig(_Strict):
    type: Literal["file", "journald"] = "file"
    path: str | None = None
    parser: Literal["auth", "nginx"] | None = None
    from_beginning: bool = False
    identifiers: list[str] = Field(default_factory=lambda: ["sshd", "sshd-session"])

    @model_validator(mode="after")
    def _check(self) -> SourceConfig:
        if self.type == "file" and (not self.path or not self.parser):
            raise ValueError("file sources need 'path' and 'parser' (auth or nginx)")
        return self


class GeoIPConfig(_Strict):
    database: str | None = None
    static_map: str | None = None


class DashboardConfig(_Strict):
    host: str = "127.0.0.1"
    port: int = 8080


class TelegramConfig(_Strict):
    min_severity: Literal["low", "medium", "high", "critical"] = "medium"
    batch_interval: float = Field(default=10.0, ge=1.0)
    max_alerts_per_message: int = Field(default=10, ge=1, le=30)


class Config(_Strict):
    database: str = "data/siem.db"
    rules: str = "rules"
    retention_days: int = Field(default=30, ge=1)
    log_timezone: str = "local"
    store_all_http: bool = False
    ignore_networks: list[str] = Field(default_factory=list)
    poll_interval: float = Field(default=1.0, gt=0)
    sources: list[SourceConfig] = Field(default_factory=list)
    geoip: GeoIPConfig = Field(default_factory=GeoIPConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)

    def timezone(self) -> tzinfo:
        if self.log_timezone.lower() == "local":
            tz = datetime.now().astimezone().tzinfo
            assert tz is not None
            return tz
        return ZoneInfo(self.log_timezone)


def _resolve(base: Path, value: str | None) -> str | None:
    if not value:
        return value
    p = Path(value)
    return str(p if p.is_absolute() else (base / p).resolve())


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("SIEM_CONFIG", "config.yml"))
    data = {}
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    elif path.name != "config.yml" or "SIEM_CONFIG" in os.environ:
        raise FileNotFoundError(f"config file not found: {path}")
    cfg = Config.model_validate(data)

    base = path.resolve().parent
    cfg.database = os.environ.get("SIEM_DB") or _resolve(base, cfg.database) or cfg.database
    cfg.rules = _resolve(base, cfg.rules) or cfg.rules
    cfg.geoip.database = _resolve(base, cfg.geoip.database)
    cfg.geoip.static_map = _resolve(base, cfg.geoip.static_map)
    for src in cfg.sources:
        src.path = _resolve(base, src.path)
    if host := os.environ.get("SIEM_DASHBOARD_HOST"):
        cfg.dashboard.host = host
    if port := os.environ.get("SIEM_DASHBOARD_PORT"):
        cfg.dashboard.port = int(port)
    return cfg
