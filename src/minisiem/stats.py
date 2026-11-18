"""``siem stats``: a README-ready Markdown summary of what the sensor has seen."""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime

from .storage import SQLiteStorage

# The standard library has no country names; label the usual suspects, show ISO codes
# for everything else.
_COUNTRY = {
    "CN": "China", "US": "United States", "RU": "Russia", "BR": "Brazil",
    "IN": "India", "DE": "Germany", "NL": "Netherlands", "FR": "France",
    "GB": "United Kingdom", "VN": "Vietnam", "KR": "South Korea", "ID": "Indonesia",
    "SG": "Singapore", "HK": "Hong Kong", "TW": "Taiwan", "JP": "Japan",
    "TR": "Türkiye", "UA": "Ukraine", "IR": "Iran", "BG": "Bulgaria", "RO": "Romania",
}  # fmt: skip


def mask_ip(ip: str) -> str:
    """Hide the host part: 203.0.113.42 -> 203.0.113.x, 2001:db8:1:2::5 -> 2001:db8:1::/48."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return ".".join(ip.split(".")[:3]) + ".x"
    net = ipaddress.ip_network(f"{addr}/48", strict=False)
    return str(net)


def _md(text: object) -> str:
    """Escape a value for a Markdown table cell and render it as inline code."""
    s = str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ")
    return f"`{s}`" if s else "`(empty)`"


def _country(code: str | None) -> str:
    if not code or code == "??":
        return "Unknown"
    return f"{_COUNTRY.get(code, code)} ({code})" if code in _COUNTRY else code


def render_markdown(
    db: SQLiteStorage, days: int = 30, limit: int = 10, full_ips: bool = False
) -> str:
    now = time.time()
    since = now - days * 86400
    s = db.summary(since)
    users = db.top_users(since, limit)
    ips = db.top_ips(since, limit)
    countries = [c for c in db.countries(since)][:limit]
    rules = db.alerts_by_rule(since)

    first = s["first_event"]
    period_start = max(since, datetime.fromisoformat(first).timestamp()) if first else since
    actual_days = max((now - period_start) / 86400, 1 / 24)
    per_day = s["ssh_attempts"] / actual_days

    def d(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d")

    out: list[str] = []
    out.append(f"### Results: last {days} days")
    out.append("")
    out.append(
        f"_Generated with `siem stats --days {days}` on {d(now)}, "
        f"covering {d(period_start)} to {d(now)}._"
    )
    out.append("")
    out += [
        "| Metric | Value |",
        "|---|---:|",
        f"| SSH login attempts | {s['ssh_attempts']:,} |",
        f"| Average SSH attempts per day | {per_day:,.0f} |",
        f"| Distinct usernames tried | {s['usernames']:,} |",
        f"| Suspicious HTTP requests | {s['http_suspicious']:,} |",
        f"| Unique attacking IP addresses | {s['attacker_ips']:,} |",
        f"| Alerts raised | {s['alerts']:,} |",
        "",
    ]

    out += ["#### Most-tried usernames", "", "| # | Username | Attempts | Source IPs |",
            "|---:|---|---:|---:|"]  # fmt: skip
    for i, u in enumerate(users, 1):
        out.append(f"| {i} | {_md(u['user'])} | {u['count']:,} | {u['ips']:,} |")
    if not users:
        out.append("| - | (none) | 0 | 0 |")
    out.append("")

    label = "IP" if full_ips else "Network (host part masked)"
    out += ["#### Top attacking addresses", "", f"| # | {label} | Country | SSH | HTTP |",
            "|---:|---|---|---:|---:|"]  # fmt: skip
    for i, r in enumerate(ips, 1):
        ip = r["ip"] if full_ips else mask_ip(r["ip"])
        out.append(f"| {i} | {_md(ip)} | {_country(r['country'])} | {r['ssh']:,} | {r['http']:,} |")
    if not ips:
        out.append("| - | (none) | | 0 | 0 |")
    out.append("")

    total = sum(c["count"] for c in countries) or 1
    out += ["#### Top source countries", "", "| # | Country | Events | Share | IPs |",
            "|---:|---|---:|---:|---:|"]  # fmt: skip
    for i, c in enumerate(countries, 1):
        out.append(
            f"| {i} | {_country(c['country'])} | {c['count']:,} | "
            f"{100 * c['count'] / total:.1f}% | {c['ips']:,} |"
        )
    if not countries:
        out.append("| - | (none) | 0 | | 0 |")
    out.append("")

    out += ["#### Alerts by rule", "", "| Rule | ATT&CK | Alerts |", "|---|---|---:|"]
    for r in rules:
        out.append(f"| {r['rule_name']} | {', '.join(r['mitre'])} | {r['count']:,} |")
    if not rules:
        out.append("| (none) | | 0 |")
    out.append("")
    if not full_ips:
        out.append("_IP addresses are truncated to protect personal data._")
        out.append("")
    return "\n".join(out)
