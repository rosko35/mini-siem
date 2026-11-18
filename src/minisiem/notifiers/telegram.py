"""Telegram Bot API notifier with batching and flood protection.

Alerts are queued and flushed by a background task at most once every
``batch_interval`` seconds. One flush sends **one** message containing up to
``max_per_message`` alerts; anything beyond that is folded into a per-rule
summary line. So no matter how hard the server is being hammered, the chat
receives at most ``60 / batch_interval`` messages per minute.

The bot token is part of the API URL, so it is never logged: errors are
reported by status code / exception type only.
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import logging
from collections import Counter, deque

import httpx

from ..mitre import technique_name
from ..models import Alert, Severity
from .base import Notifier

log = logging.getLogger(__name__)

MAX_TEXT = 4000  # Telegram's hard limit is 4096 characters
_ICON = {
    Severity.LOW: "ℹ️",
    Severity.MEDIUM: "⚠️",
    Severity.HIGH: "\U0001f6a8",
    Severity.CRITICAL: "\U0001f525",
}


class TelegramNotifier(Notifier):
    name = "telegram"

    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        min_severity: Severity = Severity.MEDIUM,
        batch_interval: float = 10.0,
        max_per_message: int = 10,
        max_queue: int = 1000,
        api_base: str = "https://api.telegram.org",
        client: httpx.AsyncClient | None = None,
        hostname: str | None = None,
    ) -> None:
        if not token or not chat_id:
            raise ValueError("Telegram token and chat id are required")
        self._url = f"{api_base}/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.min_severity = min_severity
        self.batch_interval = batch_interval
        self.max_per_message = max_per_message
        self.hostname = hostname
        self._queue: deque[Alert] = deque(maxlen=max_queue)
        self._dropped = 0
        self._client = client or httpx.AsyncClient(timeout=15.0)
        self._owns_client = client is None
        self._task: asyncio.Task | None = None
        self.sent_messages = 0
        self._sleep = asyncio.sleep  # replaceable in tests

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="telegram-flush")

    async def send(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        if len(self._queue) == self._queue.maxlen:
            self._dropped += 1
        self._queue.append(alert)

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.batch_interval)
            try:
                await self.flush()
            except Exception:  # pragma: no cover - keep the loop alive
                log.exception("telegram flush failed")

    async def flush(self) -> bool:
        """Send one message with whatever is queued. Returns True if something was sent."""
        if not self._queue:
            return False
        alerts = list(self._queue)
        self._queue.clear()
        dropped, self._dropped = self._dropped, 0
        text = self.format(alerts[: self.max_per_message], alerts[self.max_per_message :], dropped)
        return await self._post(text)

    def format(self, shown: list[Alert], rest: list[Alert], dropped: int = 0) -> str:
        host = f" on <b>{html.escape(self.hostname)}</b>" if self.hostname else ""
        total = len(shown) + len(rest) + dropped
        lines = [f"<b>mini-siem</b>{host}: {total} alert{'s' if total != 1 else ''}"]
        for a in shown:
            mitre = ", ".join(f"{t} {technique_name(t)}".strip() for t in a.mitre)
            where = f" {a.country}" if a.country else ""
            lines.append(
                f"\n{_ICON[a.severity]} <b>{html.escape(a.rule_name)}</b> "
                f"[{a.severity.label()}]\n"
                f"{html.escape(a.message)}\n"
                f"<code>{html.escape(a.key)}</code>{html.escape(where)} · "
                f"{a.ts.strftime('%Y-%m-%d %H:%M:%S %Z').strip()}"
                + (f"\n<i>{html.escape(mitre)}</i>" if mitre else "")
            )
        if rest or dropped:
            by_rule = Counter(a.rule_id for a in rest)
            summary = ", ".join(f"{html.escape(r)} ×{n}" for r, n in by_rule.most_common(8))
            extra = len(rest) + dropped
            lines.append(f"\n… and {extra} more" + (f": {summary}" if summary else ""))
        text = "\n".join(lines)
        if len(text) > MAX_TEXT:
            text = text[: MAX_TEXT - 20] + "\n…(truncated)"
        return text

    async def _post(self, text: str, attempts: int = 3) -> bool:
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        for attempt in range(1, attempts + 1):
            try:
                resp = await self._client.post(self._url, json=payload)
            except httpx.HTTPError as exc:
                log.warning("telegram request failed (%s), attempt %d", type(exc).__name__, attempt)
                await self._sleep(min(2**attempt, 30))
                continue
            if resp.status_code == 200:
                self.sent_messages += 1
                return True
            if resp.status_code == 429:
                retry_after = 5
                with contextlib.suppress(ValueError, KeyError, TypeError):
                    retry_after = int(resp.json()["parameters"]["retry_after"])
                log.warning("telegram rate limited, retrying in %ss", retry_after)
                await self._sleep(min(retry_after, 60))
                continue
            log.warning("telegram API returned HTTP %s", resp.status_code)
            return False  # 4xx other than 429: bad token/chat id, retrying will not help
        return False

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        with contextlib.suppress(Exception):
            await self.flush()
        if self._owns_client:
            await self._client.aclose()
