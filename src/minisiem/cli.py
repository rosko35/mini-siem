"""Command line interface: ``siem <command>``."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import logging
import signal
import sys
from pathlib import Path

from dotenv import load_dotenv

from . import __version__
from .config import Config, load_config
from .detection import RuleError, load_rules

log = logging.getLogger("minisiem")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # httpx logs full request URLs at INFO, and the Telegram URL contains the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _notifiers(cfg: Config):
    from .notifiers import build_notifiers

    return build_notifiers(
        telegram_min_severity=cfg.telegram.min_severity,
        batch_interval=cfg.telegram.batch_interval,
        max_per_message=cfg.telegram.max_alerts_per_message,
    )


def _install_stop_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):  # Windows
            loop.add_signal_handler(sig, stop.set)


def _warn_if_exposed(cfg: Config) -> None:
    from .web import AuthSettings

    host = cfg.dashboard.host
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback and not AuthSettings.from_env().enabled:
        log.warning(
            "dashboard binds to %s without authentication. Fine inside a container that "
            "publishes on 127.0.0.1 only; otherwise set SIEM_DASHBOARD_USER/PASSWORD.",
            host,
        )


def _uvicorn_server(cfg: Config):
    import uvicorn

    from .web import create_app

    _warn_if_exposed(cfg)
    app = create_app(cfg.database, rules_dir=cfg.rules)
    config = uvicorn.Config(
        app,
        host=cfg.dashboard.host,
        port=cfg.dashboard.port,
        log_level="warning",
        access_log=False,
        server_header=False,
        proxy_headers=False,
    )
    return uvicorn.Server(config)


# -- commands -------------------------------------------------------------------


def cmd_monitor(cfg: Config, args: argparse.Namespace) -> int:
    from .monitor import Monitor
    from .storage import SQLiteStorage

    async def main() -> None:
        storage = SQLiteStorage(cfg.database)
        stop = asyncio.Event()
        _install_stop_handlers(stop)
        monitor = Monitor(cfg, storage, _notifiers(cfg))
        try:
            await monitor.run(stop)
        finally:
            storage.close()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
    return 0


def cmd_dashboard(cfg: Config, args: argparse.Namespace) -> int:
    server = _uvicorn_server(cfg)
    log.info("dashboard on http://%s:%d", cfg.dashboard.host, cfg.dashboard.port)
    server.run()
    return 0


def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    """Monitor and dashboard in one process (what the container runs)."""
    from .monitor import Monitor
    from .storage import SQLiteStorage

    async def main() -> None:
        storage = SQLiteStorage(cfg.database)  # creates the schema before the API reads it
        stop = asyncio.Event()
        monitor = Monitor(cfg, storage, _notifiers(cfg))
        server = _uvicorn_server(cfg)
        monitor_task = asyncio.create_task(monitor.run(stop))
        monitor_task.add_done_callback(lambda _: setattr(server, "should_exit", True))
        log.info("dashboard on http://%s:%d", cfg.dashboard.host, cfg.dashboard.port)
        try:
            await server.serve()  # returns on SIGINT/SIGTERM
        finally:
            stop.set()
            with contextlib.suppress(Exception):
                await monitor_task
            storage.close()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
    return 0


def cmd_replay(cfg: Config, args: argparse.Namespace) -> int:
    from .monitor import Monitor
    from .notifiers import ConsoleNotifier, NotifierHub
    from .storage import SQLiteStorage

    if args.notify:
        notifier = _notifiers(cfg)
    elif args.quiet:
        notifier = NotifierHub([])
    else:
        notifier = NotifierHub([ConsoleNotifier()])
    storage = SQLiteStorage(cfg.database)
    monitor = Monitor(cfg, storage, notifier)
    try:
        counters = asyncio.run(monitor.replay([Path(f) for f in args.files], args.parser))
    finally:
        storage.close()
    print(
        f"replayed {counters.lines} lines: {counters.events} events, "
        f"{counters.stored} stored, {counters.alerts} alerts"
    )
    for rule, n in sorted(counters.by_rule.items(), key=lambda kv: -kv[1]):
        print(f"  {rule:32} {n}")
    return 0


def cmd_stats(cfg: Config, args: argparse.Namespace) -> int:
    from .stats import render_markdown
    from .storage import SQLiteStorage

    if not Path(cfg.database).exists():
        print(f"database {cfg.database} does not exist", file=sys.stderr)
        return 1
    db = SQLiteStorage(cfg.database, readonly=True)
    try:
        print(render_markdown(db, days=args.days, limit=args.limit, full_ips=args.full_ips))
    finally:
        db.close()
    return 0


def cmd_check_rules(cfg: Config, args: argparse.Namespace) -> int:
    path = args.path or cfg.rules
    try:
        rules = load_rules(path)
    except RuleError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    for r in rules:
        state = "" if r.enabled else " (disabled)"
        print(f"  {r.id:28} {r.type:9} {r.severity:8} {', '.join(r.mitre)}{state}")
    print(f"OK: {len(rules)} rules in {path}")
    return 0


def cmd_prune(cfg: Config, args: argparse.Namespace) -> int:
    from .storage import SQLiteStorage

    days = args.days or cfg.retention_days
    db = SQLiteStorage(cfg.database)
    try:
        ev, al = db.prune(days)
    finally:
        db.close()
    print(f"deleted {ev} events and {al} alerts older than {days} days")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="siem", description="mini-siem: log monitoring and IDS")
    p.add_argument("-c", "--config", help="YAML config file (default: $SIEM_CONFIG or config.yml)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="monitor logs and serve the dashboard").set_defaults(func=cmd_run)
    sub.add_parser("monitor", help="monitor logs only").set_defaults(func=cmd_monitor)
    sub.add_parser("dashboard", help="serve the dashboard only").set_defaults(func=cmd_dashboard)

    r = sub.add_parser("replay", help="process existing log files once (demo / backfill)")
    r.add_argument("--parser", required=True, choices=["auth", "nginx", "journald"])
    r.add_argument("--notify", action="store_true", help="send alerts to configured notifiers")
    r.add_argument("-q", "--quiet", action="store_true", help="do not log individual alerts")
    r.add_argument("files", nargs="+")
    r.set_defaults(func=cmd_replay)

    s = sub.add_parser("stats", help="print a Markdown summary for the README")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--full-ips", action="store_true", help="do not mask IP addresses")
    s.set_defaults(func=cmd_stats)

    c = sub.add_parser("check-rules", help="validate rule files")
    c.add_argument("path", nargs="?")
    c.set_defaults(func=cmd_check_rules)

    pr = sub.add_parser("prune", help="apply the retention period now")
    pr.add_argument("--days", type=int)
    pr.set_defaults(func=cmd_prune)
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=False)
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    try:
        cfg = load_config(args.config)
    except Exception as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    return args.func(cfg, args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
