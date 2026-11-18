"""IP -> ISO country code lookups.

Uses a local MaxMind GeoLite2-Country / GeoLite2-City or DB-IP "IP to
Country Lite" ``.mmdb`` file when one is configured. Nothing is downloaded or
bundled; without a database every lookup returns ``None`` ("unknown") and
the rest of the system works unchanged.

A small static CIDR -> country map can be layered on top. It is used by the
demo (documentation address ranges never resolve to a country) and can label
your own networks.
"""

from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class GeoIP:
    def __init__(self, database: str | None = None, static_map: str | None = None) -> None:
        self._reader = None
        self._static: list[tuple[Network, str]] = []
        if database:
            path = Path(database)
            if path.is_file():
                try:
                    import maxminddb

                    self._reader = maxminddb.open_database(str(path))
                    log.info("GeoIP database loaded: %s", path)
                except Exception as exc:  # corrupt file, wrong format, ...
                    log.warning("cannot open GeoIP database %s: %s", path, exc)
            else:
                log.warning("GeoIP database %s not found; countries will be unknown", path)
        if static_map:
            self._static = load_static_map(static_map)
        self.lookup = lru_cache(maxsize=65536)(self._lookup)

    @property
    def enabled(self) -> bool:
        return self._reader is not None or bool(self._static)

    def _lookup(self, ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, country in self._static:
            if addr.version == net.version and addr in net:
                return country
        if self._reader is None or not addr.is_global:
            return None
        try:
            record = self._reader.get(ip)
        except Exception:
            return None
        if not isinstance(record, dict):
            return None
        for key in ("country", "registered_country"):
            iso = (record.get(key) or {}).get("iso_code")
            if iso:
                return str(iso).upper()
        return None

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()


def load_static_map(path: str) -> list[tuple[Network, str]]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out: list[tuple[Network, str]] = []
    for cidr, country in (data.get("networks") or {}).items():
        out.append((ipaddress.ip_network(cidr, strict=False), str(country).upper()))
    # Most specific network first.
    out.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return out
