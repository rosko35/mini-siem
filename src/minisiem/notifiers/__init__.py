"""Alert notifiers. Add a new one by subclassing ``Notifier`` and wiring it up
in ``build_notifiers``."""

from __future__ import annotations

import logging
import os
import socket

from ..models import Severity
from .base import Notifier, NotifierHub
from .console import ConsoleNotifier
from .telegram import TelegramNotifier

log = logging.getLogger(__name__)


def build_notifiers(
    *,
    telegram_min_severity: str = "medium",
    batch_interval: float = 10.0,
    max_per_message: int = 10,
    console_min_severity: str = "low",
    env: dict[str, str] | None = None,
) -> NotifierHub:
    """Console logging is always on; Telegram is added when the token and
    chat id are present in the environment (or ``.env``)."""
    env = dict(os.environ) if env is None else env
    notifiers: list[Notifier] = [ConsoleNotifier(Severity.parse(console_min_severity))]
    token = env.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = env.get("TELEGRAM_CHAT_ID", "").strip()
    if token and chat_id:
        notifiers.append(
            TelegramNotifier(
                token,
                chat_id,
                min_severity=Severity.parse(telegram_min_severity),
                batch_interval=batch_interval,
                max_per_message=max_per_message,
                hostname=env.get("SIEM_HOSTNAME") or socket.gethostname(),
            )
        )
        log.info("Telegram notifications enabled (min severity: %s)", telegram_min_severity)
    else:
        log.info("TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID not set: alerts go to the log only")
    return NotifierHub(notifiers)


__all__ = ["ConsoleNotifier", "Notifier", "NotifierHub", "TelegramNotifier", "build_notifiers"]
