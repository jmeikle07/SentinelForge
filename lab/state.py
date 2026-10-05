"""Atomic, locked JSON state files. A corrupt file is quarantined, never overwritten."""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:  # Windows
    import msvcrt as _msvcrt
except ImportError:  # POSIX
    _msvcrt = None
    import fcntl as _fcntl

log = logging.getLogger(__name__)

_MISSING = object()
_thread_lock = threading.RLock()
_held = threading.local()  # lock files this thread already holds (re-entrancy)
LOCK_TIMEOUT = 10.0


def _replace(src, dst, attempts: int = 50) -> None:
    """os.replace with retry: on Windows it raises PermissionError transiently when
    another handle (scanner, indexer) briefly holds the target."""
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.01 * (i + 1))


class StateCorrupt(RuntimeError):
    """The state file could not be parsed; it was moved to <name>.corrupt."""


@contextmanager
def file_lock(lock_path, timeout: float | None = None):
    """Exclusive cross-process (and cross-thread) lock held for a whole with-block.

    A kernel advisory lock on an open descriptor of `lock_path` (msvcrt.locking on Windows,
    fcntl.flock elsewhere). The OS releases it when the holder dies, so there is no stale-lock
    heuristic and no takeover race. The lock file is never deleted (deleting it is what makes
    unlink-based locks racy). Re-entrant within a thread."""
    lock_path = Path(lock_path)
    key = os.path.normcase(os.path.abspath(lock_path))
    if key in getattr(_held, "paths", ()):
        yield
        return
    timeout = LOCK_TIMEOUT if timeout is None else timeout
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _thread_lock:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    if _msvcrt is not None:
                        os.lseek(fd, 0, os.SEEK_SET)
                        _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                    else:
                        _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"could not lock {lock_path}") from None
                    time.sleep(0.005)
            if not hasattr(_held, "paths"):
                _held.paths = set()
            _held.paths.add(key)
            try:
                yield
            finally:
                _held.paths.discard(key)
                if _msvcrt is not None:
                    os.lseek(fd, 0, os.SEEK_SET)
                    _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
                else:
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _locked(path: Path):
    return file_lock(path.with_name(path.name + ".lock"))


def _quarantine_path(path: Path) -> Path:
    """<name>.corrupt if free, else <name>.corrupt.<utc timestamp>[-n]: never overwrite evidence."""
    first = path.with_suffix(".corrupt")
    if not first.exists():
        return first
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    n = 0
    while True:
        cand = first.with_name(f"{first.name}.{stamp}" + (f"-{n}" if n else ""))
        if not cand.exists():
            return cand
        n += 1


def _read_unlocked(path: Path, default: Any) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if default is _MISSING:
            raise
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        quarantine = _quarantine_path(path)
        _replace(path, quarantine)
        log.error("corrupt state file %s moved to %s: %s", path, quarantine, exc)
        raise StateCorrupt(f"{path} is corrupt (moved to {quarantine}): {exc}") from exc


def _write_unlocked(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2)  # serialize first: failure leaves old file intact
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        _replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read(path, default: Any = _MISSING) -> Any:
    path = Path(path)
    if not path.parent.exists():  # nothing can exist here yet
        if default is _MISSING:
            raise FileNotFoundError(path)
        return default
    with _locked(path):
        return _read_unlocked(path, default)


def write(path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    json.dumps(data, indent=2)  # fail early, before taking the lock
    with _locked(path):
        _write_unlocked(path, data)


def update(path, fn, default: Any = _MISSING) -> Any:
    """Read-modify-write under ONE lock hold. fn(current) -> new value, written atomically and
    returned. current is `default` when the file is missing (FileNotFoundError if no default).
    If fn raises, nothing is written. A corrupt file is quarantined and StateCorrupt raised."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _locked(path):
        new = fn(_read_unlocked(path, default))
        _write_unlocked(path, new)
        return new
