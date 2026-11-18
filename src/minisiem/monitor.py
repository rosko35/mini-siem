"""The pipeline: sources -> parser -> GeoIP -> rule engine -> storage -> notifiers."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .config import Config, SourceConfig
from .detection import RuleEngine, load_rules
from .geoip import GeoIP
from .models import Alert, Event, EventType
from .notifiers import Notifier, NotifierHub
from .parsers import Parser, get_parser
from .sources import FileTailer, JournaldSource, SourceState
from .storage import SQLiteStorage

log = logging.getLogger(__name__)

FLUSH_INTERVAL = 1.0
FLUSH_BATCH = 500
PRUNE_INTERVAL = 3600
HEARTBEAT_INTERVAL = 300


class Source(Protocol):
    key: str

    def lines(self) -> AsyncIterator[str]: ...
    def state(self) -> SourceState | None: ...


@dataclass
class Counters:
    lines: int = 0
    events: int = 0
    stored: int = 0
    alerts: int = 0
    by_rule: dict[str, int] = field(default_factory=dict)


class Monitor:
    def __init__(
        self,
        config: Config,
        storage: SQLiteStorage,
        notifier: Notifier | None = None,
        engine: RuleEngine | None = None,
        geoip: GeoIP | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.notifier = notifier or NotifierHub([])
        self.engine = engine or RuleEngine(load_rules(config.rules), config.ignore_networks)
        self.geoip = geoip or GeoIP(config.geoip.database, config.geoip.static_map)
        self.counters = Counters()
        self._pending: list[Event] = []
        self._sources: list[Source] = []

    # -- per line ----------------------------------------------------------
    def _should_store(self, event: Event) -> bool:
        if event.type != EventType.HTTP_REQUEST:
            return True
        return self.config.store_all_http or event.suspicious

    def process_line(self, parser: Parser, line: str) -> list[Alert]:
        """Parse, enrich, evaluate and buffer one line. Returns the alerts it raised."""
        self.counters.lines += 1
        event = parser.parse(line)
        if event is None:
            return []
        self.counters.events += 1
        event.country = self.geoip.lookup(event.src_ip)
        alerts = self.engine.process(event)
        if self._should_store(event):
            self._pending.append(event)
        for alert in alerts:
            alert.country = event.country if alert.src_ip == event.src_ip else None
            self.storage.add_alert(alert)
            self.counters.alerts += 1
            self.counters.by_rule[alert.rule_id] = self.counters.by_rule.get(alert.rule_id, 0) + 1
        if len(self._pending) >= FLUSH_BATCH:
            self.flush()
        return alerts

    def flush(self) -> None:
        if self._pending:
            self.storage.add_events(self._pending)
            self.counters.stored += len(self._pending)
            self._pending.clear()
        states = [s.state() for s in self._sources]
        self.storage.commit([st for st in states if st is not None])

    # -- sources -----------------------------------------------------------
    def build_source(self, sc: SourceConfig) -> tuple[Source, Parser]:
        if sc.type == "journald":
            return JournaldSource(sc.identifiers, store=self.storage), get_parser("journald")
        assert sc.path and sc.parser
        tailer = FileTailer(
            sc.path,
            from_beginning=sc.from_beginning,
            store=self.storage,
            poll_interval=self.config.poll_interval,
        )
        return tailer, get_parser(sc.parser, tz=self.config.timezone())

    async def _consume(self, source: Source, parser: Parser) -> None:
        async for line in source.lines():
            try:
                alerts = self.process_line(parser, line)
            except Exception:
                log.exception("failed to process line from %s: %r", source.key, line[:200])
                continue
            for alert in alerts:
                await self.notifier.send(alert)
            if alerts:
                self.flush()  # make alerts visible on the dashboard right away

    async def _periodic(self) -> None:
        last_prune = 0.0
        last_beat = time.monotonic()
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            self.flush()
            now = time.monotonic()
            if now - last_prune >= PRUNE_INTERVAL:
                ev, al = self.storage.prune(self.config.retention_days)
                if ev or al:
                    log.info("retention: deleted %d events and %d alerts", ev, al)
                last_prune = now
            if now - last_beat >= HEARTBEAT_INTERVAL:
                c = self.counters
                log.info(
                    "heartbeat: %d lines, %d events, %d stored, %d alerts",
                    c.lines,
                    c.events,
                    c.stored,
                    c.alerts,
                )
                last_beat = now

    async def run(self, stop: asyncio.Event | None = None) -> None:
        stop = stop or asyncio.Event()
        if not self.config.sources:
            raise RuntimeError("no sources configured")
        pairs = [self.build_source(sc) for sc in self.config.sources]
        self._sources = [s for s, _ in pairs]
        await self.notifier.start()
        tasks = [asyncio.create_task(self._consume(s, p), name=f"source:{s.key}") for s, p in pairs]
        tasks.append(asyncio.create_task(self._periodic(), name="periodic"))
        stopper = asyncio.create_task(stop.wait(), name="stop")
        log.info("monitoring %d source(s) with %d rules", len(pairs), len(self.engine.rules))
        try:
            done, _ = await asyncio.wait([*tasks, stopper], return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                if t is not stopper and t.exception():
                    log.error("task %s failed: %s", t.get_name(), t.exception())
        finally:
            for t in [*tasks, stopper]:
                t.cancel()
            for t in [*tasks, stopper]:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
            self.flush()
            await self.notifier.close()
            log.info("monitor stopped")

    # -- one-shot replay -----------------------------------------------------
    async def replay(self, files: list[Path], parser_name: str) -> Counters:
        """Process existing files once from the beginning (no following, no offsets)."""
        parser = get_parser(parser_name, tz=self.config.timezone())
        await self.notifier.start()
        try:
            for f in files:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if not line.strip():
                            continue
                        for alert in self.process_line(parser, line):
                            await self.notifier.send(alert)
            self.flush()
        finally:
            await self.notifier.close()
        return self.counters
