import asyncio
import base64

import pytest
from fastapi.testclient import TestClient

from minisiem.monitor import Monitor
from minisiem.notifiers import NotifierHub
from minisiem.storage import SQLiteStorage
from minisiem.web import AuthSettings, create_app


@pytest.fixture
def populated(scenario):
    cfg, logs = scenario
    storage = SQLiteStorage(cfg.database)
    mon = Monitor(cfg, storage, NotifierHub([]))
    asyncio.run(mon.replay([logs / "auth.log"], "auth"))
    asyncio.run(mon.replay([logs / "access.log"], "nginx"))
    storage.close()
    return cfg


@pytest.fixture
def client(populated):
    app = create_app(populated.database, rules_dir=populated.rules, auth=AuthSettings())
    return TestClient(app)


def test_summary(client):
    r = client.get("/api/summary?days=7")
    assert r.status_code == 200
    body = r.json()
    assert body["days"] == 7
    assert body["ssh_attempts"] == 8
    assert body["alerts"] == 4
    assert body["attacker_ips"] == 4


def test_top_ips_and_usernames(client):
    ips = client.get("/api/top-ips?limit=3").json()
    assert [i["ip"] for i in ips][:2] == ["198.51.100.200", "203.0.113.5"]
    assert ips[1]["country"] == "CN"
    users = client.get("/api/top-usernames").json()
    assert {"user": "root", "count": 2, "ips": 1} in users


def test_countries_hourly(client):
    countries = {c["country"]: c["count"] for c in client.get("/api/countries").json()}
    assert countries["CN"] == 14
    hourly = client.get("/api/hourly?hours=6").json()
    assert 6 <= len(hourly) <= 8
    assert set(hourly[0]) == {"hour", "ssh_attempts", "http_suspicious", "alerts"}
    assert sum(h["ssh_attempts"] for h in hourly) == 8


def test_alerts_endpoints(client):
    recent = client.get("/api/alerts/recent?limit=10").json()
    assert len(recent) == 4
    brute = next(a for a in recent if a["rule_id"] == "ssh-bruteforce")
    assert brute["severity"] == 3
    assert brute["mitre"][0]["id"] == "T1110.001"
    assert brute["mitre"][0]["url"] == "https://attack.mitre.org/techniques/T1110/001/"
    by_rule = {r["rule_id"]: r["count"] for r in client.get("/api/alerts/by-rule").json()}
    assert by_rule == {
        "ssh-bruteforce": 1,
        "web-directory-scan": 1,
        "web-path-traversal": 1,
        "web-scanner-user-agent": 1,
    }


def test_mitre_coverage_lists_rules_without_alerts(client):
    mitre = {m["id"]: m for m in client.get("/api/mitre").json()}
    assert mitre["T1110.001"]["alerts"] == 1
    assert "ssh-bruteforce" in mitre["T1110.001"]["rules"]
    assert mitre["T1078"]["alerts"] == 0  # covered by a rule, never fired
    assert mitre["T1190"]["name"] == "Exploit Public-Facing Application"


@pytest.mark.parametrize("url", ["/api/summary?days=0", "/api/top-ips?limit=1000"])
def test_parameter_validation(client, url):
    assert client.get(url).status_code == 422


def test_dashboard_page_and_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    assert '<canvas id="hourly">' in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/../storage.py").status_code == 404
    assert client.get("/assets/secret.txt").status_code == 404


def test_missing_database_returns_503(tmp_path):
    app = create_app(str(tmp_path / "nope.db"), auth=AuthSettings())
    assert TestClient(app).get("/api/summary").status_code == 503
    assert TestClient(app).get("/healthz").json()["status"] == "ok"


def test_dashboard_never_writes(populated):
    # The API uses a read-only connection; a write through it must fail.
    db = SQLiteStorage(populated.database, readonly=True)
    with pytest.raises(Exception, match="readonly"):
        db.conn.execute("DELETE FROM alerts")
    db.close()


class TestAuth:
    @pytest.fixture
    def app(self, populated):
        auth = AuthSettings(token="s3cret-token", user="admin", password="hunter2")
        return create_app(populated.database, auth=auth)

    def test_unauthenticated_is_rejected(self, app):
        c = TestClient(app)
        r = c.get("/api/summary")
        assert r.status_code == 401
        assert r.headers["www-authenticate"].startswith("Basic")
        assert c.get("/").status_code == 401
        assert c.get("/healthz").status_code == 200  # for container health checks

    def test_bearer_token(self, app):
        c = TestClient(app)
        ok = c.get("/api/summary", headers={"Authorization": "Bearer s3cret-token"})
        assert ok.status_code == 200
        bad = c.get("/api/summary", headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401

    def test_basic_auth(self, app):
        c = TestClient(app)
        good = base64.b64encode(b"admin:hunter2").decode()
        bad = base64.b64encode(b"admin:wrong").decode()
        assert c.get("/", headers={"Authorization": f"Basic {good}"}).status_code == 200
        assert c.get("/", headers={"Authorization": f"Basic {bad}"}).status_code == 401
        assert c.get("/", headers={"Authorization": "Basic !!!"}).status_code == 401


def test_auth_settings_from_env(monkeypatch):
    monkeypatch.setenv("SIEM_DASHBOARD_TOKEN", "abc")
    monkeypatch.delenv("SIEM_DASHBOARD_USER", raising=False)
    monkeypatch.delenv("SIEM_DASHBOARD_PASSWORD", raising=False)
    s = AuthSettings.from_env()
    assert s.enabled and not s.basic
    assert s.check("Bearer abc")
    assert not s.check("")
