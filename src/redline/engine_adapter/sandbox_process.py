from __future__ import annotations

import subprocess
from dataclasses import dataclass


class SandboxProcessTimeout(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxProcessResult:
    returncode: int
    stdout: str
    stderr: str


def run_sandbox_process(cmd: list[str], *, timeout_s: int, env: dict[str, str]) -> SandboxProcessResult:
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_s, env=env)
    except subprocess.TimeoutExpired as exc:
        raise SandboxProcessTimeout("replay timeout") from exc
    return SandboxProcessResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
