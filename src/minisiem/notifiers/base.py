"""Notifier interface and fan-out helper.

A notifier receives alerts one by one through ``send``. Implementations that
talk to the network must never block the pipeline: buffer in ``send`` and do
the I/O in a background task started by ``start``.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable

from ..models import Alert

log = logging.getLogger(__name__)


class Notifier(ABC):
    name: str = "notifier"

    async def start(self) -> None:  # noqa: B027 - optional hook
        """Start background work (optional)."""

    @abstractmethod
    async def send(self, alert: Alert) -> None:
        """Accept one alert. Must return quickly."""

    async def close(self) -> None:  # noqa: B027 - optional hook
        """Flush pending alerts and release resources (optional)."""


class NotifierHub(Notifier):
    """Send every alert to several notifiers; one failing does not affect the others."""

    name = "hub"

    def __init__(self, notifiers: Iterable[Notifier]) -> None:
        self.notifiers = list(notifiers)

    async def start(self) -> None:
        for n in self.notifiers:
            await n.start()

    async def send(self, alert: Alert) -> None:
        for n in self.notifiers:
            try:
                await n.send(alert)
            except Exception:  # pragma: no cover - defensive
                log.exception("notifier %s failed", n.name)

    async def close(self) -> None:
        for n in self.notifiers:
            try:
                await n.close()
            except Exception:  # pragma: no cover - defensive
                log.exception("closing notifier %s failed", n.name)
