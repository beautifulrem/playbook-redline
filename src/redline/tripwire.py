from __future__ import annotations

import contextvars
import os
import sys
from contextlib import contextmanager
from collections.abc import Iterator


class VerdictPathViolation(RuntimeError):
    """Raised when verdict-bearing code attempts external side effects."""


_ACTIVE = contextvars.ContextVar("redline_verdict_tripwire_active", default=False)
_INSTALLED = False
_FORBIDDEN_PREFIXES = (
    "ctypes",
    "os.exec",
    "os.fork",
    "socket",
    "subprocess",
)
_FORBIDDEN_EVENTS = {
    "os.chmod",
    "os.chown",
    "os.link",
    "os.mkdir",
    "os.posix_spawn",
    "os.remove",
    "os.rename",
    "os.rmdir",
    "os.spawn",
    "os.system",
    "os.symlink",
    "os.truncate",
    "os.unlink",
    "os.utime",
    "pathlib.Path.open",
    "shutil.copyfile",
    "shutil.copymode",
    "shutil.copystat",
    "shutil.copytree",
    "shutil.move",
}
_FORBIDDEN_IMPORT_PREFIXES = (
    "anthropic",
    "_ctypes",
    "cffi",
    "ctypes",
    "google.generativeai",
    "httpx",
    "openai",
    "requests",
    "xai_sdk",
)


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    if not _ACTIVE.get():
        return
    if event == "import" and args:
        module_name = str(args[0])
        if any(module_name == prefix or module_name.startswith(prefix + ".") for prefix in _FORBIDDEN_IMPORT_PREFIXES):
            raise VerdictPathViolation(f"forbidden verdict-path import: {module_name}")
    if event == "open" and args:
        mode = str(args[1]) if len(args) > 1 and args[1] is not None else "r"
        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
        if any(flag in mode for flag in ("w", "a", "x", "+")) or bool(flags & write_flags):
            raise VerdictPathViolation("forbidden verdict-path file write: open")
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
