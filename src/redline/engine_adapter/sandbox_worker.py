from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import sys
from decimal import Decimal
from pathlib import Path
from types import ModuleType

from redline.canonical import hash_obj
from redline.models import Bar, ReasonCode, ReplayPoint, ReplayTrace


def _audit_hook(event: str, args: tuple[object, ...]) -> None:
    blocked_prefixes = ("socket", "subprocess")
    blocked_events = {"os.system", "os.posix_spawn", "os.spawn", "pty.spawn"}
    if event.startswith(blocked_prefixes) or event in blocked_events:
        raise RuntimeError(f"{ReasonCode.CANDIDATE_SANDBOX_VIOLATION.value}:{event}")


def _load_strategy(strategy_path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("redline_candidate_strategy", strategy_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{ReasonCode.PARSE_ERROR.value}:cannot load strategy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "signal"):
        raise RuntimeError(f"{ReasonCode.SCHEMA_INVALID.value}:strategy missing signal()")
    return module


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
        raise RuntimeError(f"{ReasonCode.DATA_MISSING.value}:empty scenario")
    return rows


def _read_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _replay(*, package_dir: Path, scenario_id: str, scenario_path: Path, role: str) -> ReplayTrace:
    bars = _read_bars(scenario_path)
    config = _read_config(package_dir / "config.json")
    strategy = _load_strategy(package_dir / "strategy.py")
    nav = Decimal("10000")
    peak = nav
    previous_position = Decimal("0")
    trade_count = 0
    points: list[ReplayPoint] = []
    state: dict[str, object] = {}
    previous_close = bars[0].close
    for bar in bars:
        signal_value = Decimal(str(strategy.signal(bar.model_dump(mode="json"), state, config)))
        leverage = Decimal(str(config.get("leverage", "1")))
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
        "input_hash": hash_obj({"bars": bars, "config": config, "strategy": (package_dir / "strategy.py").read_text(encoding="utf-8")}),
    }
    artifact_hash = hash_obj(trace_without_hash)
    return ReplayTrace(**trace_without_hash, artifact_hash=artifact_hash)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--scenario-path", required=True)
    parser.add_argument("--role", choices=["baseline", "candidate"], required=True)
    args = parser.parse_args()
    os.environ.setdefault("TZ", "UTC")
    sys.addaudithook(_audit_hook)
    try:
        trace = _replay(
            package_dir=Path(args.package).resolve(),
            scenario_id=args.scenario_id,
            scenario_path=Path(args.scenario_path).resolve(),
            role=args.role,
        )
    except Exception as exc:  # subprocess boundary: return typed error instead of traceback contract drift
        reason = ReasonCode.ENGINE_FAILURE.value
        text = str(exc)
        for code in ReasonCode:
            if code.value in text:
                reason = code.value
                break
        print(json.dumps({"ok": False, "reason_code": reason, "message": text}, sort_keys=True))
        return 0
    print(json.dumps({"ok": True, "trace": trace.model_dump(mode="json")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

