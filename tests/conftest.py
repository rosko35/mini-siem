from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from minisiem.config import Config, GeoIPConfig, SourceConfig

ROOT = Path(__file__).resolve().parent.parent


def auth_line(ts: datetime, msg: str, prog: str = "sshd") -> str:
    return f"{ts.isoformat(timespec='microseconds')} web1 {prog}[4242]: {msg}"


def nginx_line(ts: datetime, ip: str, path: str, status: int = 200, ua: str = "Mozilla/5.0") -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"'


def attack_logs(base: datetime) -> tuple[list[str], list[str]]:
    """A small but complete scenario used by the pipeline and API tests."""
    auth: list[str] = []
    t = base
    # brute force from 203.0.113.5 (CN in the demo geo map): 8 failures in 16 s
    for i, user in enumerate(["root", "admin", "admin", "ubuntu", "root", "test", "oracle", "pi"]):
        t = base + timedelta(seconds=2 * i)
        if user not in ("root",):
            auth.append(auth_line(t, f"Invalid user {user} from 203.0.113.5 port {40000 + i}"))
            msg = f"Failed password for invalid user {user} from 203.0.113.5 port {40000 + i} ssh2"
        else:
            msg = f"Failed password for root from 203.0.113.5 port {40000 + i} ssh2"
        auth.append(auth_line(t, msg))
    # a legitimate admin login
    auth.append(
        auth_line(
            base + timedelta(minutes=1),
            "Accepted publickey for emre from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x",
        )
    )
    # noise that must be ignored
    auth.append(f"{base.isoformat()} web1 CRON[1]: pam_unix(cron:session): session opened")

    web: list[str] = []
    for i in range(25):
        web.append(nginx_line(base + timedelta(seconds=i), "198.51.100.200", f"/old{i}.php", 404))
    web.append(nginx_line(base, "203.0.113.40", "/../../etc/passwd", 400))
    web.append(nginx_line(base, "203.0.113.70", "/", 200, ua="sqlmap/1.8 (https://sqlmap.org)"))
    for i in range(5):
        web.append(nginx_line(base + timedelta(seconds=i), "192.0.2.50", f"/blog/{i}", 200))
    return auth, web


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)


@pytest.fixture
def scenario(tmp_path, now):
    auth, web = attack_logs(now)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")
    (logs / "access.log").write_text("\n".join(web) + "\n", encoding="utf-8")
    cfg = Config(
        database=str(tmp_path / "siem.db"),
        rules=str(ROOT / "rules"),
        log_timezone="UTC",
        poll_interval=0.05,
        sources=[
            SourceConfig(path=str(logs / "auth.log"), parser="auth", from_beginning=True),
            SourceConfig(path=str(logs / "access.log"), parser="nginx", from_beginning=True),
        ],
        geoip=GeoIPConfig(static_map=str(ROOT / "demo" / "demo-geo.yml")),
    )
    return cfg, logs
