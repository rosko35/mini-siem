from __future__ import annotations

import logging

from ..models import Alert, Severity
from .base import Notifier

log = logging.getLogger("minisiem.alerts")

_LEVELS = {
    Severity.LOW: logging.INFO,
    Severity.MEDIUM: logging.WARNING,
    Severity.HIGH: logging.WARNING,
    Severity.CRITICAL: logging.CRITICAL,
}


class ConsoleNotifier(Notifier):
    """Write alerts to the application log (stderr / journald / docker logs)."""

    name = "console"

    def __init__(self, min_severity: Severity = Severity.LOW) -> None:
        self.min_severity = min_severity

    async def send(self, alert: Alert) -> None:
        if alert.severity < self.min_severity:
            return
        mitre = f" [{', '.join(alert.mitre)}]" if alert.mitre else ""
        country = f" ({alert.country})" if alert.country else ""
        log.log(
            _LEVELS[alert.severity],
            "ALERT %s %s%s: %s%s",
            alert.severity.label().upper(),
            alert.rule_id,
            country,
            alert.message,
            mitre,
        )
