from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

from redline.canonical import hash_obj
from redline.models import Bar, ReasonCode, ReplayPoint, ReplayTrace, Scenario


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
        try:
            bars = _read_bars(scenario_path)
            config = _read_config(package / "config.json")
            strategy_source = (package / "strategy.py").read_text(encoding="utf-8")
        except (OSError, KeyError, ValueError) as exc:
            raise ReplayEngineError(ReasonCode.DATA_MISSING, str(exc)) from exc
        cmd = build_worker_command(package=package, scenario_id=scenario.id, scenario_path=scenario_path, role=role)
        env = {
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }
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
        try:
            signals = [Decimal(str(signal)) for signal in payload["signals"]]
        except Exception as exc:
            raise ReplayEngineError(ReasonCode.SCHEMA_INVALID, "worker returned invalid signal list") from exc
        if len(signals) != len(bars):
            raise ReplayEngineError(ReasonCode.SCHEMA_INVALID, "worker signal count mismatch")
        return _build_trace(
            scenario_id=scenario.id,
            role=role,
            bars=bars,
            config=config,
            strategy_source=strategy_source,
            signals=signals,
        )


def build_worker_command(*, package: Path, scenario_id: str, scenario_path: Path, role: str) -> list[str]:
    worker_cmd = [
        sys.executable,
        "-m",
        "redline.engine_adapter.sandbox_worker",
        "--package",
        str(package),
        "--scenario-id",
        scenario_id,
        "--scenario-path",
        str(scenario_path),
        "--role",
        role,
    ]
    sandbox_exec = _macos_sandbox_exec()
    if sandbox_exec is not None:
        return [
            sandbox_exec,
            "-p",
            "(version 1)(allow default)(deny network*)(deny process-fork)(deny file-write*)",
            *worker_cmd,
        ]
    return worker_cmd


def _macos_sandbox_exec() -> str | None:
    if os.environ.get("REDLINE_DISABLE_OS_SANDBOX") == "1":
        return None
    if platform.system() != "Darwin":
        return None
    return shutil.which("sandbox-exec")


def _read_bars(path: Path) -> list[Bar]:
    rows: list[Bar] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            rows.append(
                Bar(
                    i=i,
                    timestamp=row["timestamp"],
                    open=Decimal(row["open"]),
                    high=Decimal(row["high"]),
                    low=Decimal(row["low"]),
                    close=Decimal(row["close"]),
                )
            )
    if not rows:
        raise ValueError("empty scenario")
    return rows


def _read_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _build_trace(
    *,
    scenario_id: str,
    role: str,
    bars: list[Bar],
    config: dict[str, object],
    strategy_source: str,
    signals: list[Decimal],
) -> ReplayTrace:
    nav = Decimal("10000")
    peak = nav
    previous_position = Decimal("0")
    trade_count = 0
    points: list[ReplayPoint] = []
    previous_close = bars[0].close
    leverage = Decimal(str(config.get("leverage", "1")))
    for bar, signal_value in zip(bars, signals, strict=True):
        if not signal_value.is_finite():
            raise ReplayEngineError(ReasonCode.NONFINITE_VALUE, "non-finite signal")
        position = signal_value * leverage
        if bar.i > 0:
            ret = (bar.close - previous_close) / previous_close
            nav = nav * (Decimal("1") + position * ret)
        if position != previous_position:
            trade_count += 1
        previous_position = position
        previous_close = bar.close
        if nav > peak:
            peak = nav
        drawdown = Decimal("0") if peak == 0 else (peak - nav) / peak
        points.append(
            ReplayPoint(
                bar=bar.i,
                timestamp=bar.timestamp,
                close=bar.close,
                nav=nav,
                peak=peak,
                drawdown=drawdown,
                position=position,
            )
        )
    trace_without_hash = {
        "scenario_id": scenario_id,
        "role": role,
        "engine": "deterministic",
        "bars": len(bars),
        "trade_count": trade_count,
        "points": points,
        "input_hash": hash_obj({"bars": bars, "config": config, "strategy": strategy_source}),
    }
    artifact_hash = hash_obj(trace_without_hash)
    return ReplayTrace(**trace_without_hash, artifact_hash=artifact_hash)
