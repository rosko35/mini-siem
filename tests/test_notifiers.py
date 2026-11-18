import asyncio
import json
import logging
from datetime import UTC, datetime

import httpx
import pytest

from minisiem.models import Alert, Severity
from minisiem.notifiers import ConsoleNotifier, TelegramNotifier, build_notifiers

TOKEN = "123456:TEST-TOKEN-not-real"


def alert(rule="ssh-bruteforce", severity=Severity.HIGH, key="203.0.113.7", msg="5 failures"):
    return Alert(
        ts=datetime(2026, 11, 18, 10, 0, tzinfo=UTC),
        rule_id=rule,
        rule_name=rule.replace("-", " ").title(),
        severity=severity,
        key=key,
        message=msg,
        src_ip=key,
        mitre=["T1110.001"],
        country="NL",
    )


class Recorder:
    def __init__(self, responses=None):
        self.requests: list[httpx.Request] = []
        self.responses = list(responses or [])

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.responses:
            return self.responses.pop(0)
        return httpx.Response(200, json={"ok": True, "result": {}})

    def texts(self):
        return [json.loads(r.content)["text"] for r in self.requests]


def make(recorder, **kwargs):
    client = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    n = TelegramNotifier(TOKEN, "-100123", client=client, hostname="web1", **kwargs)

    async def no_sleep(_):
        return None

    n._sleep = no_sleep
    return n


def run(coro):
    return asyncio.run(coro)


def test_single_alert_is_sent_as_html():
    rec = Recorder()

    async def go():
        n = make(rec)
        await n.send(alert(msg="<b>not markup</b>"))
        assert await n.flush() is True
        await n.close()

    run(go())
    assert len(rec.requests) == 1
    req = rec.requests[0]
    assert req.url.path == f"/bot{TOKEN}/sendMessage"
    body = json.loads(req.content)
    assert body["chat_id"] == "-100123"
    assert body["parse_mode"] == "HTML"
    assert "&lt;b&gt;not markup&lt;/b&gt;" in body["text"]
    assert "T1110.001 Brute Force: Password Guessing" in body["text"]
    assert "web1" in body["text"]


def test_flood_is_batched_into_one_message():
    rec = Recorder()

    async def go():
        n = make(rec, max_per_message=5)
        for i in range(200):
            await n.send(alert(key=f"203.0.113.{i % 250}"))
        for _ in range(30):
            await n.send(alert(rule="web-sqli-probe"))
        await n.flush()
        assert await n.flush() is False  # queue is empty now
        await n.close()

    run(go())
    assert len(rec.requests) == 1
    text = rec.texts()[0]
    assert "230 alerts" in text
    assert "and 225 more" in text
    assert "ssh-bruteforce ×195" in text
    assert "web-sqli-probe ×30" in text
    assert len(text) <= 4096


def test_queue_bound_counts_dropped():
    rec = Recorder()

    async def go():
        n = make(rec, max_queue=10, max_per_message=2)
        for _ in range(25):
            await n.send(alert())
        await n.flush()
        await n.close()

    run(go())
    assert "25 alerts" in rec.texts()[0]


def test_min_severity_filter():
    rec = Recorder()

    async def go():
        n = make(rec, min_severity=Severity.HIGH)
        await n.send(alert(severity=Severity.MEDIUM))
        assert await n.flush() is False
        await n.close()

    run(go())
    assert rec.requests == []


def test_rate_limit_429_is_retried():
    rec = Recorder([httpx.Response(429, json={"ok": False, "parameters": {"retry_after": 3}})])

    async def go():
        n = make(rec)
        await n.send(alert())
        assert await n.flush() is True
        await n.close()

    run(go())
    assert len(rec.requests) == 2


def test_bad_token_is_not_retried_and_token_not_logged(caplog):
    rec = Recorder([httpx.Response(401, json={"ok": False})])

    async def go():
        n = make(rec)
        await n.send(alert())
        assert await n.flush() is False
        await n.close()

    with caplog.at_level(logging.WARNING):
        run(go())
    assert len(rec.requests) == 1
    assert "401" in caplog.text
    assert TOKEN not in caplog.text


def test_network_error_retries_then_gives_up(caplog):
    def boom(request):
        raise httpx.ConnectError("connection refused", request=request)

    async def go():
        n = make(boom)
        await n.send(alert())
        assert await n.flush() is False
        await n.close()

    with caplog.at_level(logging.WARNING):
        run(go())
    assert caplog.text.count("ConnectError") == 3
    assert TOKEN not in caplog.text


def test_background_loop_flushes():
    rec = Recorder()

    async def go():
        n = make(rec, batch_interval=0.01)
        n._sleep = asyncio.sleep
        await n.start()
        await n.send(alert())
        for _ in range(100):
            if rec.requests:
                break
            await asyncio.sleep(0.01)
        await n.close()

    run(go())
    assert len(rec.requests) == 1


def test_close_flushes_pending():
    rec = Recorder()

    async def go():
        n = make(rec, batch_interval=3600)
        await n.start()
        await n.send(alert())
        await n.close()

    run(go())
    assert len(rec.requests) == 1


def test_requires_credentials():
    with pytest.raises(ValueError):
        TelegramNotifier("", "1")


def test_factory_falls_back_to_console():
    hub = build_notifiers(env={})
    assert [n.name for n in hub.notifiers] == ["console"]
    hub = build_notifiers(env={"TELEGRAM_BOT_TOKEN": TOKEN, "TELEGRAM_CHAT_ID": "1"})
    assert [n.name for n in hub.notifiers] == ["console", "telegram"]
    asyncio.run(hub.close())


def test_console_notifier_logs(caplog):
    with caplog.at_level(logging.INFO, logger="minisiem.alerts"):
        asyncio.run(ConsoleNotifier().send(alert()))
    assert "ALERT HIGH ssh-bruteforce (NL): 5 failures [T1110.001]" in caplog.text
