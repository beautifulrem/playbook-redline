from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import subprocess
import sys
from decimal import Decimal, DecimalException
from pathlib import Path

from redline.canonical import CanonicalizationError, hash_obj
from redline.models import Bar, ReasonCode, ReplayPoint, ReplayTrace, Scenario

_MAX_ABS_SIGNAL = Decimal("1000")
_MAX_ABS_LEVERAGE = Decimal("1000")
_MAX_ABS_POSITION = Decimal("1000")
_MAX_ABS_NAV = Decimal("1e18")


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
        try:
            return _build_trace(
                scenario_id=scenario.id,
                role=role,
                bars=bars,
                config=config,
                strategy_source=strategy_source,
                signals=signals,
            )
        except ReplayEngineError:
            raise
        except (CanonicalizationError, DecimalException, ArithmeticError) as exc:
            raise ReplayEngineError(ReasonCode.NONFINITE_VALUE, "deterministic replay numeric bounds exceeded") from exc


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
            bar = Bar(
                i=i,
                timestamp=row["timestamp"],
                open=Decimal(row["open"]),
                high=Decimal(row["high"]),
                low=Decimal(row["low"]),
                close=Decimal(row["close"]),
            )
            _validate_bar(bar)
            rows.append(bar)
    if not rows:
        raise ValueError("empty scenario")
    return rows


def _read_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _validate_bar(bar: Bar) -> None:
    values = [bar.open, bar.high, bar.low, bar.close]
    if any(not value.is_finite() or value <= 0 for value in values):
        raise ValueError("scenario OHLC values must be finite and positive")


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
    try:
        leverage = Decimal(str(config.get("leverage", "1")))
    except Exception as exc:
        raise ReplayEngineError(ReasonCode.NONFINITE_VALUE, "invalid leverage") from exc
    _require_bounded_decimal(leverage, label="leverage", max_abs=_MAX_ABS_LEVERAGE)
    for bar, signal_value in zip(bars, signals, strict=True):
        _require_bounded_decimal(signal_value, label="signal", max_abs=_MAX_ABS_SIGNAL)
        position = signal_value * leverage
        _require_bounded_decimal(position, label="position", max_abs=_MAX_ABS_POSITION)
        if bar.i > 0:
            ret = (bar.close - previous_close) / previous_close
            nav = nav * (Decimal("1") + position * ret)
            _require_bounded_decimal(nav, label="nav", max_abs=_MAX_ABS_NAV)
        if position != previous_position:
            trade_count += 1
        previous_position = position
        previous_close = bar.close
        if nav > peak:
            peak = nav
        drawdown = Decimal("0") if peak == 0 else (peak - nav) / peak
        _require_bounded_decimal(peak, label="peak", max_abs=_MAX_ABS_NAV)
        _require_bounded_decimal(drawdown, label="drawdown")
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


def _require_bounded_decimal(value: Decimal, *, label: str, max_abs: Decimal | None = None) -> None:
    if not value.is_finite():
        raise ReplayEngineError(ReasonCode.NONFINITE_VALUE, f"non-finite {label}")
    if max_abs is not None and abs(value) > max_abs:
        raise ReplayEngineError(ReasonCode.NONFINITE_VALUE, f"{label} outside deterministic numeric bounds")
