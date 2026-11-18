"""Read-only dashboard: a JSON API plus a single static page (Chart.js + jsVectorMap).

Security posture:

* binds to 127.0.0.1 by default; reach it through an SSH tunnel;
* optional HTTP basic auth (SIEM_DASHBOARD_USER / SIEM_DASHBOARD_PASSWORD)
  and/or bearer token (SIEM_DASHBOARD_TOKEN), compared in constant time;
* opens the database read-only, never writes;
* strict security headers (CSP limited to the jsDelivr CDN).
"""

import base64
import binascii
import os
import secrets
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse

from .. import __version__
from ..detection import RuleError, load_rules
from ..mitre import technique_name, technique_tactic, technique_url
from ..storage import SQLiteStorage

STATIC = Path(__file__).parent / "static"
ASSETS = {"app.js": "text/javascript", "style.css": "text/css"}

CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class AuthSettings:
    def __init__(self, token: str = "", user: str = "", password: str = "") -> None:
        self.token = token
        self.user = user
        self.password = password

    @classmethod
    def from_env(cls) -> "AuthSettings":
        return cls(
            os.environ.get("SIEM_DASHBOARD_TOKEN", ""),
            os.environ.get("SIEM_DASHBOARD_USER", ""),
            os.environ.get("SIEM_DASHBOARD_PASSWORD", ""),
        )

    @property
    def basic(self) -> bool:
        return bool(self.user and self.password)

    @property
    def enabled(self) -> bool:
        return bool(self.token) or self.basic

    def check(self, header: str) -> bool:
        if not self.enabled:
            return True
        scheme, _, value = header.partition(" ")
        if self.token and scheme.lower() == "bearer":
            return secrets.compare_digest(value.strip().encode(), self.token.encode())
        if self.basic and scheme.lower() == "basic":
            try:
                user, _, password = base64.b64decode(value.strip()).decode().partition(":")
            except (binascii.Error, UnicodeDecodeError):
                return False
            ok_user = secrets.compare_digest(user.encode(), self.user.encode())
            ok_pass = secrets.compare_digest(password.encode(), self.password.encode())
            return ok_user and ok_pass
        return False


def get_db(request: Request) -> Iterator[SQLiteStorage]:
    """A read-only connection per request (cheap for SQLite, safe across threads)."""
    db_path = request.app.state.db_path
    if not Path(db_path).exists():
        raise HTTPException(503, "database not created yet - is the monitor running?")
    db = SQLiteStorage(db_path, readonly=True)
    try:
        yield db
    finally:
        db.close()


DB = Annotated[SQLiteStorage, Depends(get_db)]
Days = Annotated[int, Query(ge=1, le=365)]
Limit = Annotated[int, Query(ge=1, le=100)]
Hours = Annotated[int, Query(ge=1, le=24 * 31)]


def create_app(
    db_path: str,
    *,
    rules_dir: str | None = None,
    auth: "AuthSettings | None" = None,
) -> FastAPI:
    auth = auth if auth is not None else AuthSettings.from_env()
    app = FastAPI(title="mini-siem", version=__version__, docs_url=None, redoc_url=None)

    def require_auth(request: Request) -> None:
        if not auth.check(request.headers.get("authorization", "")):
            challenge = 'Basic realm="mini-siem"' if auth.basic else "Bearer"
            raise HTTPException(401, "authentication required", {"WWW-Authenticate": challenge})

    app.state.db_path = db_path

    def since(days: int) -> float:
        return time.time() - days * 86400

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    api = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

    @api.get("/summary")
    def summary(db: DB, days: Days = 7) -> dict:
        return {"days": days, **db.summary(since(days))}

    @api.get("/top-ips")
    def top_ips(db: DB, days: Days = 7, limit: Limit = 10) -> list[dict]:
        return db.top_ips(since(days), limit)

    @api.get("/top-usernames")
    def top_usernames(db: DB, days: Days = 7, limit: Limit = 10) -> list[dict]:
        return db.top_users(since(days), limit)

    @api.get("/countries")
    def countries(db: DB, days: Days = 7) -> list[dict]:
        return db.countries(since(days))

    @api.get("/hourly")
    def hourly(db: DB, hours: Hours = 48) -> list[dict]:
        return db.hourly(time.time() - hours * 3600)

    @api.get("/alerts/recent")
    def recent_alerts(db: DB, limit: Limit = 50) -> list[dict]:
        rows = db.recent_alerts(limit)
        for r in rows:
            r["mitre"] = [_technique(t) for t in r["mitre"]]
        return rows

    @api.get("/alerts/by-rule")
    def alerts_by_rule(db: DB, days: Days = 7) -> list[dict]:
        rows = db.alerts_by_rule(since(days))
        for r in rows:
            r["mitre"] = [_technique(t) for t in r["mitre"]]
        return rows

    @api.get("/mitre")
    def mitre(db: DB, days: Days = 7) -> list[dict]:
        """ATT&CK techniques covered by the loaded rules, with alert counts."""
        counts = {m["technique"]: m["count"] for m in db.mitre_counts(since(days))}
        rules: dict[str, list[str]] = {}
        if rules_dir:
            try:
                for rule in load_rules(rules_dir):
                    for t in rule.mitre:
                        rules.setdefault(t, []).append(rule.id)
            except RuleError:
                pass
        ids = sorted(set(counts) | set(rules))
        return [
            {**_technique(t), "alerts": counts.get(t, 0), "rules": rules.get(t, [])} for t in ids
        ]

    app.include_router(api)

    @app.get("/", include_in_schema=False, dependencies=[Depends(require_auth)])
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/assets/{name}", include_in_schema=False, dependencies=[Depends(require_auth)])
    def asset(name: str) -> FileResponse:
        if name not in ASSETS:
            raise HTTPException(404)
        return FileResponse(STATIC / name, media_type=ASSETS[name])

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
        )

    return app


def _technique(tid: str) -> dict:
    return {
        "id": tid,
        "name": technique_name(tid),
        "tactic": technique_tactic(tid),
        "url": technique_url(tid),
    }
