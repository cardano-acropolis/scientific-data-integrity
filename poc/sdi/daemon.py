"""Watched-folder daemon — the primary, install-anywhere capture path.

Monitors an acquisition output directory and commits each new file once it has
stopped growing (a proxy for "the instrument finished writing it"). Commits are
accumulated and flushed as a Merkle batch, so many files share one anchoring
transaction.

The watcher is a dependency-free polling loop (stdlib only) so it runs on any
machine; it uses ``watchdog`` if installed but never requires it. The polling
core (:meth:`FolderWatcher.poll_once`) takes an injectable clock and does no
sleeping, which keeps it unit-testable without threads or real time.
"""

from __future__ import annotations

import fnmatch
import os
import time
from typing import Callable

from . import batch as batch_mod, manifest as manifest_mod
from .anchor import AnchorBackend


class FolderWatcher:
    """Emit each file whose size has been stable for ``stable_seconds``."""

    def __init__(
        self,
        directory: str,
        *,
        pattern: str = "*",
        stable_seconds: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.directory = directory
        self.pattern = pattern
        self.stable_seconds = stable_seconds
        self.clock = clock
        self._sizes: dict[str, int] = {}          # path -> last-seen size
        self._stable_since: dict[str, float] = {}  # path -> time size last changed
        self._emitted: set[str] = set()

    def poll_once(self) -> list[str]:
        """Scan once; return paths that just became stable (each emitted once)."""
        now = self.clock()
        newly_stable: list[str] = []
        try:
            entries = sorted(os.listdir(self.directory))
        except OSError:
            return []
        for name in entries:
            if not fnmatch.fnmatch(name, self.pattern):
                continue
            path = os.path.join(self.directory, name)
            if not os.path.isfile(path) or path in self._emitted:
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if self._sizes.get(path) != size:
                self._sizes[path] = size
                self._stable_since[path] = now
                continue
            if now - self._stable_since[path] >= self.stable_seconds:
                self._emitted.add(path)
                newly_stable.append(path)
        return newly_stable


class Batcher:
    """Accumulate signed manifests and flush them as one anchored Merkle batch."""

    def __init__(
        self,
        backend: AnchorBackend,
        sk_hex: str,
        out_dir: str,
        *,
        batch_size: int = 8,
        sign_root: bool = True,
    ) -> None:
        self.backend = backend
        self.sk_hex = sk_hex
        self.out_dir = out_dir
        self.batch_size = batch_size
        self.sign_root = sign_root
        self._pending: list[dict] = []

    def add_file(self, path: str):
        """Hash+sign ``path``; flush automatically once the batch is full."""
        self._pending.append(manifest_mod.sign(manifest_mod.build(path), self.sk_hex))
        if len(self._pending) >= self.batch_size:
            return self.flush()
        return None

    def pending_count(self) -> int:
        return len(self._pending)

    def flush(self):
        if not self._pending:
            return None
        signed, self._pending = self._pending, []
        return batch_mod.flush_manifests(
            signed,
            self.backend,
            self.out_dir,
            signer_sk_hex=self.sk_hex if self.sign_root else None,
        )


def run_watch(
    directory: str,
    *,
    backend: AnchorBackend,
    sk_hex: str,
    out_dir: str,
    pattern: str = "*",
    batch_size: int = 8,
    batch_interval: float = 30.0,
    poll_interval: float = 1.0,
    stable_seconds: float = 2.0,
    log: Callable[[str], None] = print,
) -> None:  # pragma: no cover - long-running loop, exercised via its parts
    """Blocking watch loop: capture stable files and flush batches on
    size-or-time. Ctrl-C flushes any remainder and exits."""
    watcher = FolderWatcher(
        directory, pattern=pattern, stable_seconds=stable_seconds
    )
    batcher = Batcher(backend, sk_hex, out_dir, batch_size=batch_size)
    last_flush = time.monotonic()
    log(f"watching {directory!r} (pattern={pattern}); Ctrl-C to stop")
    try:
        while True:
            for path in watcher.poll_once():
                log(f"captured {path}")
                result = batcher.add_file(path)
                if result:
                    _log_flush(result, log)
                    last_flush = time.monotonic()
            if batcher.pending_count() and time.monotonic() - last_flush >= batch_interval:
                result = batcher.flush()
                if result:
                    _log_flush(result, log)
                last_flush = time.monotonic()
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        result = batcher.flush()
        if result:
            _log_flush(result, log)
        log("stopped")


def _log_flush(result, log) -> None:
    batch, receipt, outputs = result
    log(
        f"anchored batch root {batch.root[:16]}… ({batch.leaf_count} items) "
        f"via {receipt.backend} -> {receipt.reference}"
    )
    for name, out_path in outputs:
        log(f"  {name} -> {out_path}")
