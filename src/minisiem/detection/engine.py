"""Stateful rule evaluation.

All windows and cooldowns are evaluated on *event* time, not wall-clock
time, so replaying an old log produces exactly the alerts a live run would
have produced.
"""

from __future__ import annotations

import ipaddress
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote_plus

from ..models import Alert, Event, Severity
from .schema import Conditions, PatternRule, PatternSpec, SequenceRule, ThresholdRule

AnyRule = ThresholdRule | PatternRule | SequenceRule

GC_EVERY = 5_000  # events between sweeps of idle per-key state


@dataclass(slots=True)
class _Compiled:
    spec: PatternSpec
    regexes: list[re.Pattern[str]]


def _equal(actual: object, expected: object) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual == expected
    return str(actual) == str(expected)


def matches(event: Event, conditions: Conditions) -> bool:
    """True if every condition holds. A list means "any of these values"."""
    for name, expected in conditions.items():
        actual = event.get(name)
        if actual is None:
            return False
        options = expected if isinstance(expected, list) else [expected]
        if not any(_equal(actual, opt) for opt in options):
            return False
    return True


def excluded(event: Event, conditions: Conditions) -> bool:
    """True if *any* exclude condition holds."""
    return any(matches(event, {k: v}) for k, v in conditions.items())


def decoded_variants(value: str, rounds: int = 3) -> list[str]:
    """The raw value plus successive URL-decodings (catches %252e%252e%252f etc.)."""
    out = [value]
    for _ in range(rounds):
        nxt = unquote_plus(out[-1], errors="replace")
        if nxt == out[-1]:
            break
        out.append(nxt)
    return out


class RuleEngine:
    def __init__(self, rules: Iterable[AnyRule], ignore_networks: Iterable[str] = ()) -> None:
        self.rules = [r for r in rules if r.enabled]
        self.ignore_networks = [ipaddress.ip_network(n, strict=False) for n in ignore_networks]
        self._patterns: dict[str, list[_Compiled]] = {}
        for rule in self.rules:
            if isinstance(rule, PatternRule):
                self._patterns[rule.id] = [
                    _Compiled(
                        p,
                        [re.compile(rx, re.IGNORECASE if p.ignore_case else 0) for rx in p.regex],
                    )
                    for p in rule.patterns
                ]
        # (rule_id, key) -> deque[(ts, value)]
        self._windows: dict[tuple[str, str], deque[tuple[datetime, object]]] = {}
        # (rule_id, key) -> (last alert time, suppressed count since then)
        self._cooldowns: dict[tuple[str, str], tuple[datetime, int]] = {}
        self._seen = 0
        self.suppressed_total = 0

    # -- public ------------------------------------------------------------
    def process(self, event: Event) -> list[Alert]:
        if self._ignored(event):
            return []
        alerts: list[Alert] = []
        for rule in self.rules:
            if excluded(event, rule.exclude):
                continue
            if isinstance(rule, ThresholdRule):
                alert = self._threshold(rule, event)
            elif isinstance(rule, PatternRule):
                alert = self._pattern(rule, event)
            else:
                alert = self._sequence(rule, event)
            if alert is not None:
                alerts.append(alert)
        self._seen += 1
        if self._seen % GC_EVERY == 0:
            self._gc(event.ts)
        return alerts

    # -- rule types --------------------------------------------------------
    def _threshold(self, rule: ThresholdRule, event: Event) -> Alert | None:
        if not matches(event, rule.match):
            return None
        key = self._key(rule, event)
        if key is None:
            return None
        window = self._window(rule.id, key, event.ts, rule.window)
        window.append((event.ts, event.get(rule.distinct) if rule.distinct else None))
        count = len({v for _, v in window}) if rule.distinct else len(window)
        if count < rule.threshold:
            return None
        window.clear()
        return self._fire(rule, event, key, count, window=rule.window)

    def _pattern(self, rule: PatternRule, event: Event) -> Alert | None:
        if not matches(event, rule.match):
            return None
        hit = ""
        for compiled in self._patterns[rule.id]:
            value = event.get(compiled.spec.field)
            if value is None:
                continue
            candidates = decoded_variants(str(value)) if compiled.spec.decode else [str(value)]
            for rx in compiled.regexes:
                if any(rx.search(c) for c in candidates):
                    hit = f"{compiled.spec.field}=~/{rx.pattern}/"
                    break
            if hit:
                break
        if self._patterns[rule.id] and not hit:
            return None
        event.tags.append(rule.id)
        key = self._key(rule, event)
        if key is None:
            return None
        return self._fire(rule, event, key, 1, hit=hit)

    def _sequence(self, rule: SequenceRule, event: Event) -> Alert | None:
        is_first = matches(event, rule.match)
        is_then = matches(event, rule.followed_by)
        if not (is_first or is_then):
            return None
        key = self._key(rule, event)
        if key is None:
            return None
        window = self._window(rule.id, key, event.ts, rule.window)
        if is_then and len(window) >= rule.threshold:
            count = len(window)
            window.clear()
            return self._fire(rule, event, key, count, window=rule.window)
        if is_first:
            window.append((event.ts, None))
        return None

    # -- helpers -----------------------------------------------------------
    def _ignored(self, event: Event) -> bool:
        if not self.ignore_networks or not event.src_ip:
            return False
        try:
            ip = ipaddress.ip_address(event.src_ip)
        except ValueError:
            return False
        return any(ip in net for net in self.ignore_networks)

    @staticmethod
    def _key(rule: AnyRule, event: Event) -> str | None:
        value = event.get(rule.group_by)
        return None if value is None or value == "" else str(value)

    def _window(self, rule_id: str, key: str, now: datetime, seconds: int):
        window = self._windows.setdefault((rule_id, key), deque())
        while window and (now - window[0][0]).total_seconds() > seconds:
            window.popleft()
        return window

    def _fire(
        self, rule: AnyRule, event: Event, key: str, count: int, *, window: int = 0, hit: str = ""
    ) -> Alert | None:
        ck = (rule.id, key)
        last = self._cooldowns.get(ck)
        if last and (event.ts - last[0]).total_seconds() < rule.cooldown:
            self._cooldowns[ck] = (last[0], last[1] + 1)
            self.suppressed_total += 1
            return None
        suppressed = last[1] if last else 0
        self._cooldowns[ck] = (event.ts, 0)

        context = {
            "key": key,
            "count": count,
            "window": window,
            "src_ip": event.src_ip or "-",
            "user": event.user or "-",
            "path": event.get("path", "-"),
            "user_agent": event.get("user_agent", "-"),
            "match": hit,
        }
        if rule.message:
            try:
                message = rule.message.format_map(context)
            except (KeyError, ValueError, IndexError):
                message = rule.message
        else:
            message = f"{rule.name}: {rule.group_by}={key}"
            if window:
                message += f" ({count} events in {window}s)"
        if suppressed:
            message += f" [+{suppressed} suppressed during cooldown]"
        return Alert(
            ts=event.ts,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=Severity.parse(rule.severity),
            key=key,
            message=message,
            src_ip=event.src_ip,
            count=count,
            mitre=list(rule.mitre),
            sample=event.raw[:500],
        )

    def _gc(self, now: datetime) -> None:
        horizon = {r.id: getattr(r, "window", 0) for r in self.rules}
        for ck, window in list(self._windows.items()):
            if not window or (now - window[-1][0]).total_seconds() > horizon.get(ck[0], 0):
                del self._windows[ck]
        cooldown = {r.id: r.cooldown for r in self.rules}
        for ck, (ts, _) in list(self._cooldowns.items()):
            if (now - ts).total_seconds() > cooldown.get(ck[0], 0):
                del self._cooldowns[ck]

    def state_size(self) -> int:
        return len(self._windows) + len(self._cooldowns)
