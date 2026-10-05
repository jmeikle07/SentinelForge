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

log = logging.getLogger(__name__)

_MISSING = object()
_thread_lock = threading.RLock()
LOCK_TIMEOUT = 10.0
LOCK_STALE_AFTER = 30.0


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
def _locked(path: Path):
    """In-process RLock plus a cross-process lockfile (O_EXCL) next to the state file."""
    lock_path = path.with_name(path.name + ".lock")
    with _thread_lock:
        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except (FileExistsError, PermissionError):  # PermissionError: Windows delete-pending
                try:
                    if time.time() - lock_path.stat().st_mtime > LOCK_STALE_AFTER:
                        lock_path.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"could not lock {path}")
                time.sleep(0.01)
        try:
            yield
        finally:
            lock_path.unlink(missing_ok=True)


def read(path, default: Any = _MISSING) -> Any:
    path = Path(path)
    with _locked(path.parent / path.name):
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            if default is _MISSING:
                raise
            return default
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            quarantine = path.with_suffix(".corrupt")
            _replace(path, quarantine)
            log.error("corrupt state file %s moved to %s: %s", path, quarantine, exc)
            raise StateCorrupt(f"{path} is corrupt (moved to {quarantine}): {exc}") from exc


def write(path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2)  # serialize first: failure leaves old file intact
    with _locked(path):
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
