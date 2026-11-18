import asyncio
import os

from minisiem.sources import FileTailer, JournaldSource, MemoryOffsetStore, SourceState


def append(path, text):
    with open(path, "ab") as fh:
        fh.write(text.encode())


def test_starts_at_end_by_default(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "old line\n")
    t = FileTailer(str(log))
    assert t.poll() == []
    append(log, "new line\n")
    assert t.poll() == ["new line"]


def test_from_beginning(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "a\nb\n")
    assert FileTailer(str(log), from_beginning=True).poll() == ["a", "b"]


def test_partial_line_is_buffered(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(b"")
    t = FileTailer(str(log))
    t.poll()
    append(log, "first half")
    assert t.poll() == []
    append(log, " second half\nnext")
    assert t.poll() == ["first half second half"]
    # State points after the last complete line, not after the buffered fragment.
    assert t.state().offset == len("first half second half\n")


def test_truncation_copytruncate(tmp_path):
    log = tmp_path / "access.log"
    append(log, "one\ntwo\n")
    t = FileTailer(str(log), from_beginning=True)
    assert t.poll() == ["one", "two"]
    with open(log, "wb"):
        pass  # truncate in place, same inode
    append(log, "three\n")
    assert t.poll() == ["three"]


def test_rotation_create_mode_drains_old_file(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "one\n")
    t = FileTailer(str(log), from_beginning=True)
    assert t.poll() == ["one"]
    append(log, "two\n")  # written just before rotation, not yet read
    os.replace(log, tmp_path / "auth.log.1")
    append(log, "three\n")
    assert t.poll() == ["two", "three"]
    append(log, "four\n")
    assert t.poll() == ["four"]


def test_missing_file_then_created(tmp_path):
    log = tmp_path / "later.log"
    t = FileTailer(str(log), from_beginning=True)
    assert t.poll() == []
    append(log, "hello\n")
    assert t.poll() == ["hello"]


def test_resume_from_saved_offset(tmp_path):
    log = tmp_path / "auth.log"
    store = MemoryOffsetStore()
    append(log, "a\nb\n")
    t = FileTailer(str(log), from_beginning=True, store=store)
    assert t.poll() == ["a", "b"]
    store.save_state(t.state())

    append(log, "c\n")
    t2 = FileTailer(str(log), from_beginning=True, store=store)
    assert t2.poll() == ["c"]


def test_resume_after_rotation_while_stopped(tmp_path):
    log = tmp_path / "auth.log"
    store = MemoryOffsetStore()
    append(log, "a\n")
    t = FileTailer(str(log), from_beginning=True, store=store)
    t.poll()
    store.save_state(t.state())

    append(log, "b\n")  # never read before shutdown
    os.replace(log, tmp_path / "auth.log.1")
    append(log, "c\n")
    t2 = FileTailer(str(log), store=store)
    assert t2.poll() == ["b", "c"]


def test_saved_offset_beyond_size_restarts(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "x\n")
    store = MemoryOffsetStore()
    store.save_state(SourceState(f"file:{os.path.abspath(log)}", os.stat(log).st_ino, 10_000))
    assert FileTailer(str(log), store=store).poll() == ["x"]


def test_async_lines_commits_only_consumed(tmp_path):
    log = tmp_path / "auth.log"
    append(log, "l1\nl2\nl3\n")
    t = FileTailer(str(log), from_beginning=True, poll_interval=0.01)

    async def take_two():
        gen = t.lines()
        got = [await anext(gen), await anext(gen)]
        await gen.aclose()
        return got

    assert asyncio.run(take_two()) == ["l1", "l2"]
    # l2 was handed out but its consumer never asked for more, so only l1 is committed.
    assert t.state().offset == len("l1\n")


def test_journald_command_uses_cursor():
    store = MemoryOffsetStore()
    src = JournaldSource(store=store)
    assert "--lines=0" in src.command()
    store.save_state(SourceState(src.key, cursor="s=1;i=2"))
    src2 = JournaldSource(store=store)
    assert "--after-cursor=s=1;i=2" in src2.command()
    assert "--identifier=sshd-session" in src2.command()
