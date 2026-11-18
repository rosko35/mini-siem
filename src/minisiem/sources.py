"""Log sources: a polling ``tail -F`` for files and a ``journalctl -f`` reader.

Both sources are async iterators of raw text lines and expose a ``state()``
that the monitor persists *after* the corresponding events have been written
to the database. On restart reading resumes from the saved position, which
gives at-least-once processing without re-reading whole files.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger(__name__)

MAX_READ = 4 * 1024 * 1024  # bytes per poll, so a huge backlog cannot exhaust memory
NL = b"\n"
Entry = tuple[str, int, int]  # (line, inode, file offset just after the line)


@dataclass(slots=True)
class SourceState:
    key: str
    inode: int = 0
    offset: int = 0
    cursor: str | None = None


class OffsetStore(Protocol):
    def load_state(self, key: str) -> SourceState | None: ...

    def save_state(self, state: SourceState) -> None: ...


class MemoryOffsetStore:
    """Offset store for tests and one-shot replays."""

    def __init__(self) -> None:
        self.states: dict[str, SourceState] = {}

    def load_state(self, key: str) -> SourceState | None:
        return self.states.get(key)

    def save_state(self, state: SourceState) -> None:
        self.states[state.key] = SourceState(state.key, state.inode, state.offset, state.cursor)


class FileTailer:
    """Follow a file like ``tail -F``.

    The file is opened on every poll instead of being held open. That keeps
    the code identical on Linux and Windows (where an open handle blocks
    renames) and means we never pin a deleted, rotated file on disk.

    Rotation handling:

    * **create mode** (logrotate default, rsyslog): the path suddenly has a
      different inode. Unread lines at the end of the old file are drained
      from ``<path>.1`` if a file with the old inode is found there.
    * **copytruncate**: same inode but the size shrank below our offset, so
      we start again from 0.

    ``state()`` reports the position *after the last line handed to the
    consumer*, not after the last byte read, so persisting it never skips
    lines that were read but not yet processed.
    """

    def __init__(
        self,
        path: str,
        *,
        from_beginning: bool = False,
        store: OffsetStore | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        self.path = path
        self.key = f"file:{os.path.abspath(path)}"
        self.from_beginning = from_beginning
        self.store = store
        self.poll_interval = poll_interval
        self._inode: int | None = None
        self._offset = 0  # bytes read from the current file, including the partial buffer
        self._buf = b""
        self._done = (0, 0)  # (inode, offset) just after the last consumed line

    # -- state -------------------------------------------------------------
    def state(self) -> SourceState:
        return SourceState(self.key, self._done[0], self._done[1])

    def _initialise(self, st: os.stat_result) -> list[Entry]:
        saved = self.store.load_state(self.key) if self.store else None
        self._inode = st.st_ino
        entries: list[Entry] = []
        if saved is None:
            self._offset = 0 if self.from_beginning else st.st_size
            log.info("tailing %s from %s", self.path, "start" if self._offset == 0 else "end")
        elif saved.inode == st.st_ino and saved.offset <= st.st_size:
            self._offset = saved.offset
            log.info("resuming %s at byte %d", self.path, self._offset)
        else:
            # Rotated (or truncated) while we were not running.
            if saved.inode != st.st_ino and (rotated := self._find_rotated(saved.inode)):
                entries = self._read_rest(rotated, saved.inode, saved.offset)
                log.info("draining %d lines from rotated %s", len(entries), rotated)
            self._offset = 0
        self._done = (st.st_ino, self._offset)
        return entries

    # -- reading -----------------------------------------------------------
    def _find_rotated(self, inode: int) -> str | None:
        if not inode:
            return None
        for candidate in (f"{self.path}.1", f"{self.path}.0"):
            try:
                if os.stat(candidate).st_ino == inode:
                    return candidate
            except OSError:
                continue
        return None

    def _read_rest(self, path: str, inode: int, offset: int) -> list[Entry]:
        """Read everything after ``offset`` from a finished (rotated) file."""
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                data = fh.read()
        except OSError:
            return []
        entries = _split(data, inode, offset)
        tail = data[data.rfind(NL) + 1 :]
        if tail.strip():  # the old file ended without a newline
            entries.append((_decode(tail), inode, offset + len(data)))
        return entries

    def poll_entries(self) -> list[Entry]:
        """Return ``(line, inode, end_offset)`` for complete lines appended since last poll."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []  # between rename and re-create during rotation, or not created yet
        entries: list[Entry] = []
        if self._inode is None:
            entries.extend(self._initialise(st))
        elif st.st_ino != self._inode:
            rotated = self._find_rotated(self._inode)
            if rotated:
                start = self._offset - len(self._buf)  # re-read the partial line, if any
                entries.extend(self._read_rest(rotated, self._inode, start))
            log.info("%s was rotated, reopening", self.path)
            self._inode, self._offset, self._buf = st.st_ino, 0, b""
            if not entries:
                self._done = (st.st_ino, 0)
        elif st.st_size < self._offset:
            log.info("%s was truncated, reading from start", self.path)
            self._offset, self._buf = 0, b""
            self._done = (st.st_ino, 0)

        if st.st_size > self._offset:
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(self._offset)
                    data = fh.read(MAX_READ)
            except OSError as exc:
                log.warning("cannot read %s: %s", self.path, exc)
                return entries
            base = self._offset - len(self._buf)
            self._offset += len(data)
            data = self._buf + data
            cut = data.rfind(NL) + 1
            self._buf = data[cut:]
            entries.extend(_split(data[:cut], st.st_ino, base))
        return entries

    def commit(self, entry: Entry) -> None:
        self._done = (entry[1], entry[2])

    def poll(self) -> list[str]:
        """Like ``poll_entries`` but marks everything as consumed (tests, replays)."""
        entries = self.poll_entries()
        if entries:
            self.commit(entries[-1])
        return [e[0] for e in entries]

    async def lines(self) -> AsyncIterator[str]:
        while True:
            batch = self.poll_entries()
            for entry in batch:
                yield entry[0]
                self.commit(entry)  # runs once the consumer asks for the next line
            await asyncio.sleep(0 if batch else self.poll_interval)


def _split(data: bytes, inode: int, base: int) -> list[Entry]:
    """Split complete lines out of ``data`` which starts at file offset ``base``."""
    entries: list[Entry] = []
    pos = base
    for chunk in data.split(NL)[:-1]:
        pos += len(chunk) + 1
        if chunk.strip():
            entries.append((_decode(chunk), inode, pos))
    return entries


def _decode(chunk: bytes) -> str:
    return chunk.decode("utf-8", "replace").rstrip("\r")


_CURSOR_RE = re.compile(r'"__CURSOR"\s*:\s*"([^"]+)"')


class JournaldSource:
    """Stream sshd records from ``journalctl -f -o json``.

    The journal cursor of the last line read is persisted, so after a restart
    reading continues with ``--after-cursor`` and nothing is missed.
    """

    def __init__(
        self,
        identifiers: list[str] | None = None,
        *,
        store: OffsetStore | None = None,
        journalctl: str = "journalctl",
        restart_delay: float = 5.0,
    ) -> None:
        self.identifiers = identifiers or ["sshd", "sshd-session"]
        self.key = "journald:" + ",".join(self.identifiers)
        self.store = store
        self.journalctl = journalctl
        self.restart_delay = restart_delay
        saved = store.load_state(self.key) if store else None
        self.cursor: str | None = saved.cursor if saved else None

    def state(self) -> SourceState:
        return SourceState(self.key, cursor=self.cursor)

    def command(self) -> list[str]:
        cmd = [self.journalctl, "--follow", "--output=json", "--no-pager"]
        for ident in self.identifiers:
            cmd.append(f"--identifier={ident}")
        if self.cursor:
            cmd.append(f"--after-cursor={self.cursor}")
        else:
            cmd.append("--lines=0")
        return cmd

    async def lines(self) -> AsyncIterator[str]:
        if shutil.which(self.journalctl) is None:
            raise RuntimeError(f"{self.journalctl} not found; journald source is unavailable")
        while True:
            cmd = self.command()
            log.info("starting %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            assert proc.stdout is not None
            try:
                while raw := await proc.stdout.readline():
                    line = raw.decode("utf-8", "replace")
                    yield line
                    if m := _CURSOR_RE.search(line):
                        self.cursor = m.group(1)  # only after the line was processed
            finally:
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
            log.warning("journalctl exited (%s), restarting in %.0fs", proc.returncode,
                        self.restart_delay)
            await asyncio.sleep(self.restart_delay)
