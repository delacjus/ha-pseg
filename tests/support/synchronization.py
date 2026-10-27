"""Bounded test handshakes that observe, but never replace, real serialization."""

from __future__ import annotations

import asyncio
import threading

TIMEOUT = 10


def wait_event(event: threading.Event, boundary: str, timeout: float = TIMEOUT) -> None:
    """Require an arrival or release, with a useful failure instead of a hang."""
    if not event.wait(timeout):
        raise AssertionError(f"Timed out after {timeout}s waiting for {boundary}")


async def wait_event_async(event: threading.Event, boundary: str) -> None:
    """Wait without blocking the Home Assistant event loop."""
    await asyncio.to_thread(wait_event, event, boundary)


def join_thread(thread: threading.Thread, boundary: str) -> None:
    """Drain a started worker; callers release its gates in finally first."""
    if thread.ident is None:
        return
    thread.join(TIMEOUT)
    if thread.is_alive():
        raise AssertionError(f"Timed out after {TIMEOUT}s joining {boundary}")


async def wait_task(task, boundary: str):
    """Bound task completion and preserve its original exception on failure."""
    try:
        return await asyncio.wait_for(task, TIMEOUT)
    except TimeoutError as err:
        raise AssertionError(f"Timed out after {TIMEOUT}s waiting for {boundary}") from err


class ObservedLock:
    """Signal an actual failed acquisition, then wait on the original RLock."""

    def __init__(self, lock, boundary: str) -> None:
        self.lock = lock
        self.boundary = boundary
        self.contended = threading.Event()

    def __enter__(self):
        if not self.lock.acquire(blocking=False):
            self.contended.set()
            if not self.lock.acquire(timeout=TIMEOUT):
                raise AssertionError(f"Timed out after {TIMEOUT}s acquiring {self.boundary}")
        return self

    def acquire(self, *args, **kwargs):
        """Preserve production's nonblocking cookie-property probes unchanged."""
        return self.lock.acquire(*args, **kwargs)

    def release(self):
        return self.lock.release()

    def __exit__(self, *_exc):
        self.lock.release()


class ObservedAsyncLock:
    """Observe the real asyncio lock immediately before a contended acquire."""

    def __init__(self, lock: asyncio.Lock, boundary: str) -> None:
        self.lock = lock
        self.boundary = boundary
        self.contended = threading.Event()

    async def __aenter__(self):
        if self.lock.locked():
            self.contended.set()
        await wait_task(self.lock.acquire(), self.boundary)
        return self

    async def __aexit__(self, *_exc):
        self.lock.release()
