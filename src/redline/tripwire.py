from __future__ import annotations

import contextvars
import sys
from contextlib import contextmanager
from collections.abc import Iterator


class VerdictPathViolation(RuntimeError):
    """Raised when verdict-bearing code attempts external side effects."""


_ACTIVE = contextvars.ContextVar("redline_verdict_tripwire_active", default=False)
_INSTALLED = False
_FORBIDDEN_PREFIXES = (
    "socket",
    "subprocess",
)
_FORBIDDEN_EVENTS = {
    "os.system",
    "os.posix_spawn",
    "os.spawn",
}


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    if not _ACTIVE.get():
        return
    if event in _FORBIDDEN_EVENTS or any(event.startswith(prefix) for prefix in _FORBIDDEN_PREFIXES):
        raise VerdictPathViolation(f"forbidden verdict-path side effect: {event}")


def _install_once() -> None:
    global _INSTALLED
    if not _INSTALLED:
        sys.addaudithook(_audit_hook)
        _INSTALLED = True


@contextmanager
def verdict_path_tripwire() -> Iterator[None]:
    _install_once()
    token = _ACTIVE.set(True)
    try:
        yield
    finally:
        _ACTIVE.reset(token)
