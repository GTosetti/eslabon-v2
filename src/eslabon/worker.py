"""Run archive reading + analysis in a child process with a hard wall-clock limit.

Parsing hostile input can hang (crafted tar loops, slow streams, regex blow-ups) or
crash a native library. Doing it in a spawned child lets the parent enforce a
deadline and turn any crash into a non-ok status instead of losing the scan.

Trust note on the result queue: multiprocessing.Queue pickles the object the child
puts and the parent unpickles it. The only producer is our own ``_child_main``,
running our own code, and it only ever puts a ``ScanResult`` built by us. The
hostile archive bytes are data inside that object, never a pickle stream. A child
compromised at the native level would already run with the parent's privileges,
so the queue does not widen the trust boundary. The parent still checks the type
of what it receives and fails closed on anything else.
"""

from __future__ import annotations

import multiprocessing
import queue
import time
from collections.abc import Callable
from typing import Any

from eslabon.model import ScanResult

_POLL_S = 0.2
_JOIN_S = 5.0


def _error_result(status: str, error: str) -> ScanResult:
    return ScanResult(status=status, findings=[], anomalies=[], error=error)


def _child_main(q: Any, fn: Callable[..., ScanResult], args: tuple) -> None:
    """Child entry point. Must stay module-level (spawn pickles it by reference)."""
    try:
        result = fn(*args)
        if not isinstance(result, ScanResult):
            result = _error_result("parse_error", "worker error: bad result type")
    except BaseException as exc:  # every failure must become a result
        # Only the exception type name: the message may carry attacker content.
        result = _error_result("parse_error", f"worker error: {type(exc).__name__}")
    q.put(result)
    # Returning normally lets multiprocessing flush the queue's feeder thread
    # before the process exits, so the result is not lost on a fast exit.


_NOTHING = object()


def _receive(q: Any, timeout: float | None) -> Any:
    """One read from the queue: blocking up to ``timeout``, or non-blocking if None.

    Returns ``_NOTHING`` if empty. An unreadable payload (e.g. the child died
    mid-write) becomes a parse_error result rather than an exception.
    """
    try:
        if timeout is None:
            return q.get_nowait()
        return q.get(timeout=timeout)
    except queue.Empty:
        return _NOTHING
    except Exception as exc:
        return _error_result("parse_error", f"worker error: {type(exc).__name__}")


def _validate(got: Any) -> ScanResult:
    if isinstance(got, ScanResult):
        return got
    return _error_result("parse_error", "worker error: bad result type")


def _stop(p: Any) -> None:
    """Terminate, then kill if needed, and reap the child so it is not a zombie."""
    if p.is_alive():
        p.terminate()
        p.join(_JOIN_S)
    if p.is_alive():
        p.kill()
        p.join(_JOIN_S)


def run_isolated(
    fn: Callable[..., ScanResult], args: tuple, timeout_s: float
) -> ScanResult:
    """Run ``fn(*args)`` in a spawned child; never wait longer than ``timeout_s``.

    ``fn`` must be a module-level function (spawn requirement). Returns the child's
    ScanResult, or status ``timeout`` / ``parse_error``; never ``ok`` on failure.
    """
    start = time.monotonic()
    deadline = start + timeout_s
    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_child_main, args=(q, fn, args), daemon=True)
    result: ScanResult | None = None
    try:
        p.start()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result = _error_result("timeout", "worker timeout")
                break
            got = _receive(q, min(_POLL_S, remaining))
            if got is _NOTHING and not p.is_alive():
                # Child is gone. A result may have been flushed just before exit.
                got = _receive(q, None)
                if got is _NOTHING:
                    p.join(_JOIN_S)
                    result = _error_result(
                        "parse_error", f"worker exited with code {p.exitcode}"
                    )
                    break
            if got is _NOTHING:
                continue
            result = _validate(got)
            p.join(_JOIN_S)
            break
    finally:
        _stop(p)
        q.close()
        q.join_thread()
        if not p.is_alive():
            p.close()
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
