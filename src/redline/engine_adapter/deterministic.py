from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from redline.models import ReasonCode, ReplayTrace, Scenario


class ReplayEngineError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class DeterministicReplayEngine:
    name = "deterministic"

    def replay(self, *, package: Path, scenario: Scenario, role: str, timeout_s: int = 5) -> ReplayTrace:
        scenario_path = Path(scenario.path)
        if not scenario_path.is_absolute():
            scenario_path = Path.cwd() / scenario_path
        cmd = [
            sys.executable,
            "-m",
            "redline.engine_adapter.sandbox_worker",
            "--package",
            str(package),
            "--scenario-id",
            scenario.id,
            "--scenario-path",
            str(scenario_path),
            "--role",
            role,
        ]
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = env.get("PYTHONHASHSEED", "0")
        env["TZ"] = "UTC"
        try:
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_s, env=env)
        except subprocess.TimeoutExpired as exc:
            raise ReplayEngineError(ReasonCode.ENGINE_FAILURE, "replay timeout") from exc
        if proc.returncode != 0:
            raise ReplayEngineError(ReasonCode.ENGINE_FAILURE, proc.stderr.strip() or "worker failed")
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ReplayEngineError(ReasonCode.PARSE_ERROR, proc.stdout) from exc
        if not payload.get("ok"):
            reason = ReasonCode(payload.get("reason_code", ReasonCode.ENGINE_FAILURE.value))
            raise ReplayEngineError(reason, payload.get("message", reason.value))
        return ReplayTrace.model_validate(payload["trace"])

