from __future__ import annotations

import argparse
import ast
import csv
import importlib.util
import json
import os
import re
import resource
import site
import sys
import sysconfig
from decimal import Decimal
from pathlib import Path
from types import ModuleType

from redline.models import Bar, ReasonCode

_MAX_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
_MAX_CPU_SECONDS = 3
_MAX_SIGNAL_TEXT_BYTES = 64
_DECIMAL_SIGNAL_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$")
_ALLOWED_STATIC_MODULES = {"__future__", "collections", "decimal", "fractions", "math", "statistics", "typing"}
_FORBIDDEN_ENTROPY_MODULES = {"datetime", "random", "secrets", "time", "uuid"}
_FORBIDDEN_REFLECTION_MODULES = {"inspect", "operator", "platform"}
_FORBIDDEN_STATIC_MODULES = {
    "builtins",
    "cffi",
    "configparser",
    "ctypes",
    "dbm",
    "fileinput",
    "genericpath",
    "glob",
    "importlib",
    "io",
    "linecache",
    "logging",
    "ntpath",
    "os",
    "pathlib",
    "posixpath",
    "pydoc",
    "runpy",
    "shutil",
    "shelve",
    "sqlite3",
    "socket",
    "subprocess",
    "sys",
    "tarfile",
    "tempfile",
    "zipfile",
    *_FORBIDDEN_ENTROPY_MODULES,
    *_FORBIDDEN_REFLECTION_MODULES,
}
_FORBIDDEN_DYNAMIC_CALLS = {
    "__import__",
    "ascii",
    "compile",
    "delattr",
    "dir",
    "eval",
    "exec",
    "format",
    "getattr",
    "globals",
    "hash",
    "id",
    "locals",
    "object",
    "print",
    "repr",
    "setattr",
    "str",
    "set",
    "frozenset",
    "type",
    "vars",
}
_FORBIDDEN_MODULE_GLOBAL_NAMES = {"__builtins__", "__cached__", "__file__", "__loader__", "__package__", "__spec__"}
_FORBIDDEN_FILE_READ_CALLS = {"open", "read_bytes", "read_text"}
_FORBIDDEN_FILE_WRITE_CALLS = {
    "chmod",
    "hardlink_to",
    "lchmod",
    "link_to",
    "mkdir",
    "rename",
    "replace",
    "rmdir",
    "symlink_to",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}
_FORBIDDEN_FILE_CONSTRUCTOR_CALLS = {"FileIO", "fdopen"}
_FORBIDDEN_LOADER_ACCESS_CALLS = {"get_data", "set_data"}
_FORBIDDEN_FILE_METADATA_CALLS = {
    "absolute",
    "exists",
    "expanduser",
    "glob",
    "home",
    "is_dir",
    "is_file",
    "is_mount",
    "is_socket",
    "is_symlink",
    "iterdir",
    "lstat",
    "owner",
    "readlink",
    "resolve",
    "rglob",
    "samefile",
    "stat",
}
_FORBIDDEN_NAME_REFERENCES = (
    _FORBIDDEN_DYNAMIC_CALLS
    | _FORBIDDEN_FILE_READ_CALLS
    | _FORBIDDEN_FILE_WRITE_CALLS
    | _FORBIDDEN_FILE_CONSTRUCTOR_CALLS
    | _FORBIDDEN_LOADER_ACCESS_CALLS
    | _FORBIDDEN_FILE_METADATA_CALLS
)
_FORBIDDEN_ENTROPY_ATTRS = {
    "choice",
    "choices",
    "getrandbits",
    "monotonic",
    "perf_counter",
    "process_time",
    "randint",
    "random",
    "randrange",
    "sleep",
    "time",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
    "uniform",
    "urandom",
    "uuid4",
}


def _make_audit_hook(allowed_read_roots: tuple[Path, ...], dynamic_exec_guard: dict[str, bool] | None = None):
    path_type = os.PathLike
    reason = ReasonCode.CANDIDATE_SANDBOX_VIOLATION.value

    def audit_hook(event: str, args: tuple[object, ...]) -> None:
        blocked_prefixes = ("ctypes", "socket", "subprocess", "os.exec", "os.fork")
        blocked_events = {
            "os.chdir",
            "os.chmod",
            "os.chown",
            "os.link",
            "os.listdir",
            "os.mkdir",
            "os.posix_spawn",
            "os.remove",
            "os.rename",
            "os.rmdir",
            "os.scandir",
            "os.spawn",
            "os.stat",
            "os.symlink",
            "os.system",
            "os.truncate",
            "os.unlink",
            "os.urandom",
            "os.utime",
            "pty.spawn",
            "shutil.copyfile",
            "shutil.copymode",
            "shutil.copystat",
            "shutil.copytree",
            "shutil.move",
            "tempfile.mkstemp",
            "tempfile.mkdtemp",
        }
        if event.startswith(blocked_prefixes) or event in blocked_events:
            raise RuntimeError(f"{reason}:{event}")
        if event == "exec" and args:
            filename = str(getattr(args[0], "co_filename", ""))
            reject_dynamic_exec = dynamic_exec_guard is None or dynamic_exec_guard.get("enabled", True)
            if reject_dynamic_exec and filename.startswith("<") and not filename.startswith("<frozen "):
                raise RuntimeError(f"{reason}:exec-dynamic")
        if event == "import" and args:
            module_name = str(args[0])
            module_root = module_name.split(".", 1)[0]
            if (
                module_root in _FORBIDDEN_STATIC_MODULES
                or module_name in {"_ctypes", "ctypes", "cffi"}
                or module_name.startswith(("ctypes.", "cffi."))
            ):
                raise RuntimeError(f"{reason}:import-{module_name}")
        if event == "open" and args:
            target = args[0]
            if not isinstance(target, (str, bytes, path_type)):
                return
            mode = str(args[1]) if len(args) > 1 and args[1] is not None else "r"
            flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
            if any(flag in mode for flag in ("w", "a", "x", "+")) or bool(flags & write_flags):
                raise RuntimeError(f"{reason}:open-write")
            path = Path(target).resolve()
            if allowed_read_roots and not any(path == root or root in path.parents for root in allowed_read_roots):
                raise RuntimeError(f"{reason}:open-outside-sandbox")

    return audit_hook


def _load_strategy(strategy_path: Path) -> ModuleType:
    _reject_entropy_sources(strategy_path)
    spec = importlib.util.spec_from_file_location("redline_candidate_strategy", strategy_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{ReasonCode.PARSE_ERROR.value}:cannot load strategy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "signal"):
        raise RuntimeError(f"{ReasonCode.SCHEMA_INVALID.value}:strategy missing signal()")
    return module


def _reject_entropy_sources(strategy_path: Path) -> None:
    reason = ReasonCode.CANDIDATE_SANDBOX_VIOLATION.value
    try:
        tree = ast.parse(strategy_path.read_text(encoding="utf-8"), filename=str(strategy_path))
    except SyntaxError as exc:
        raise RuntimeError(f"{ReasonCode.PARSE_ERROR.value}:cannot parse strategy") from exc
    numeric_names = _numeric_assignment_names(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_root = alias.name.split(".", 1)[0]
                if module_root not in _ALLOWED_STATIC_MODULES:
                    raise RuntimeError(f"{reason}:import-{module_root}")
                if module_root in _FORBIDDEN_STATIC_MODULES:
                    raise RuntimeError(f"{reason}:import-{module_root}")
        elif isinstance(node, ast.ImportFrom):
            module_root = (node.module or "").split(".", 1)[0]
            if module_root not in _ALLOWED_STATIC_MODULES:
                raise RuntimeError(f"{reason}:import-{module_root}")
            if module_root in _FORBIDDEN_STATIC_MODULES:
                raise RuntimeError(f"{reason}:import-{module_root}")
            for alias in node.names:
                if alias.name.startswith("_") or alias.name in _FORBIDDEN_MODULE_GLOBAL_NAMES:
                    raise RuntimeError(f"{reason}:module-global-import-{alias.name}")
                alias_root = alias.name.split(".", 1)[0]
                if alias_root in _FORBIDDEN_STATIC_MODULES:
                    raise RuntimeError(f"{reason}:import-{alias_root}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_DYNAMIC_CALLS:
                raise RuntimeError(f"{reason}:dynamic-code-{node.func.id}")
            if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_FILE_READ_CALLS:
                raise RuntimeError(f"{reason}:file-read-{node.func.id}")
            if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_FILE_WRITE_CALLS:
                raise RuntimeError(f"{reason}:file-write-{node.func.id}")
            if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_FILE_CONSTRUCTOR_CALLS:
                raise RuntimeError(f"{reason}:file-constructor-{node.func.id}")
            if isinstance(node.func, ast.Call):
                raise RuntimeError(f"{reason}:dynamic-call-result")
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_FILE_READ_CALLS:
                raise RuntimeError(f"{reason}:file-read-{node.func.attr}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_FILE_WRITE_CALLS:
                raise RuntimeError(f"{reason}:file-write-{node.func.attr}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_FILE_CONSTRUCTOR_CALLS:
                raise RuntimeError(f"{reason}:file-constructor-{node.func.attr}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_LOADER_ACCESS_CALLS:
                raise RuntimeError(f"{reason}:loader-file-access-{node.func.attr}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_DYNAMIC_CALLS:
                raise RuntimeError(f"{reason}:dynamic-code-{node.func.attr}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_FILE_METADATA_CALLS:
                raise RuntimeError(f"{reason}:file-metadata-{node.func.attr}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in _FORBIDDEN_ENTROPY_ATTRS:
                raise RuntimeError(f"{reason}:entropy-{node.func.attr}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "format_map"}:
                raise RuntimeError(f"{reason}:dynamic-format-{node.func.attr}")
            if isinstance(node.func, ast.Subscript):
                raise RuntimeError(f"{reason}:dynamic-subscript-call")
        elif isinstance(node, ast.JoinedStr):
            raise RuntimeError(f"{reason}:dynamic-format-string")
        elif isinstance(node, (ast.Set, ast.SetComp)):
            raise RuntimeError(f"{reason}:unordered-collection")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and not _is_numeric_modulo(node, numeric_names):
            raise RuntimeError(f"{reason}:dynamic-format-string")
        elif isinstance(node, ast.Attribute) and node.attr in {"format", "format_map"}:
            raise RuntimeError(f"{reason}:dynamic-format-{node.attr}")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise RuntimeError(f"{reason}:private-attribute-{node.attr}")
        elif isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_STATIC_MODULES:
            raise RuntimeError(f"{reason}:module-reexport-{node.attr}")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr.endswith("__"):
            raise RuntimeError(f"{reason}:dynamic-dunder-{node.attr}")
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_MODULE_GLOBAL_NAMES:
            raise RuntimeError(f"{reason}:module-global-{node.id}")
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAME_REFERENCES:
            if node.id in _FORBIDDEN_DYNAMIC_CALLS:
                raise RuntimeError(f"{reason}:dynamic-code-name-{node.id}")
            if node.id in _FORBIDDEN_FILE_READ_CALLS:
                raise RuntimeError(f"{reason}:file-read-name-{node.id}")
            if node.id in _FORBIDDEN_FILE_WRITE_CALLS:
                raise RuntimeError(f"{reason}:file-write-name-{node.id}")
            if node.id in _FORBIDDEN_FILE_CONSTRUCTOR_CALLS:
                raise RuntimeError(f"{reason}:file-constructor-name-{node.id}")
            if node.id in _FORBIDDEN_LOADER_ACCESS_CALLS:
                raise RuntimeError(f"{reason}:loader-file-access-name-{node.id}")
            raise RuntimeError(f"{reason}:file-metadata-name-{node.id}")
        elif isinstance(node, ast.Name) and node.id.startswith("__") and node.id.endswith("__"):
            raise RuntimeError(f"{reason}:dynamic-dunder-name-{node.id}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            _reject_forbidden_string(node.value, reason)


def _numeric_assignment_names(tree: ast.AST) -> set[str]:
    assignments: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            assignments.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            assignments.setdefault(node.target.id, []).append(node.value)
    numeric_names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, values in assignments.items():
            if name not in numeric_names and values and all(_is_numeric_expr(value, numeric_names) for value in values):
                numeric_names.add(name)
                changed = True
    return numeric_names


def _is_numeric_modulo(node: ast.BinOp, numeric_names: set[str]) -> bool:
    return _is_numeric_expr(node.left, numeric_names) and _is_numeric_expr(node.right, numeric_names)


def _is_numeric_expr(node: ast.AST | None, numeric_names: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, int) and not isinstance(node.value, bool)
    if isinstance(node, ast.Name):
        return node.id in numeric_names
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _is_numeric_expr(node.operand, numeric_names)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"int", "Decimal"}:
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv)):
        return _is_numeric_expr(node.left, numeric_names) and _is_numeric_expr(node.right, numeric_names)
    return False


def _reject_forbidden_string(value: str, reason: str) -> None:
    if "__" in value:
        raise RuntimeError(f"{reason}:dynamic-dunder-string")
    if value in _FORBIDDEN_DYNAMIC_CALLS:
        raise RuntimeError(f"{reason}:dynamic-code-string-{value}")
    if (
        value in _FORBIDDEN_FILE_READ_CALLS
        or value in _FORBIDDEN_FILE_WRITE_CALLS
        or value in _FORBIDDEN_FILE_METADATA_CALLS
        or value in _FORBIDDEN_FILE_CONSTRUCTOR_CALLS
        or value in _FORBIDDEN_LOADER_ACCESS_CALLS
    ):
        raise RuntimeError(f"{reason}:file-access-string-{value}")
    if value in _FORBIDDEN_ENTROPY_ATTRS:
        raise RuntimeError(f"{reason}:entropy-string-{value}")
    if value.split(".", 1)[0] in _FORBIDDEN_STATIC_MODULES:
        raise RuntimeError(f"{reason}:import-string-{value}")


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
        raise RuntimeError(f"{ReasonCode.DATA_MISSING.value}:empty scenario")
    return rows


def _validate_bar(bar: Bar) -> None:
    values = [bar.open, bar.high, bar.low, bar.close]
    if any(not value.is_finite() or value <= 0 for value in values):
        raise RuntimeError(f"{ReasonCode.DATA_MISSING.value}:scenario OHLC values must be finite and positive")


def _read_config(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _coerce_signal_value(raw: object) -> Decimal:
    reason = ReasonCode.CANDIDATE_SANDBOX_VIOLATION.value
    if isinstance(raw, bool):
        raise RuntimeError(f"{reason}:signal-bool")
    if isinstance(raw, int):
        value = Decimal(raw)
    elif isinstance(raw, Decimal):
        value = raw
    elif isinstance(raw, str):
        text = raw.strip()
        if len(text.encode("utf-8")) > _MAX_SIGNAL_TEXT_BYTES or _DECIMAL_SIGNAL_RE.fullmatch(text) is None:
            raise RuntimeError(f"{reason}:signal-string")
        value = Decimal(text)
    else:
        raise RuntimeError(f"{reason}:signal-type-{type(raw).__name__}")
    if not value.is_finite():
        raise RuntimeError(f"{reason}:signal-nonfinite")
    return value


def _run_signals(*, package_dir: Path, bars: list[Bar], allowed_read_roots: tuple[Path, ...]) -> list[str]:
    config = _read_config(package_dir / "config.json")
    dynamic_exec_guard = {"enabled": False}
    sys.addaudithook(_make_audit_hook(allowed_read_roots, dynamic_exec_guard))
    strategy = _load_strategy(package_dir / "strategy.py")
    dynamic_exec_guard["enabled"] = True
    signals: list[str] = []
    state: dict[str, object] = {}
    for bar in bars:
        signal_value = _coerce_signal_value(strategy.signal(bar.model_dump(mode="json"), state, config))
        signals.append(str(signal_value))
    return signals


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--scenario-path", required=True)
    parser.add_argument("--role", choices=["baseline", "candidate"], required=True)
    args = parser.parse_args()
    json_dumps = json.dumps
    stdout_write = sys.stdout.write
    os.environ.setdefault("TZ", "UTC")
    sys.dont_write_bytecode = True
    _apply_resource_limits()
    try:
        bars = _read_bars(Path(args.scenario_path).resolve())
    except Exception as exc:
        stdout_write(json_dumps({"ok": False, "reason_code": ReasonCode.DATA_MISSING.value, "message": str(exc)}, sort_keys=True))
        return 0
    roots = {Path(args.package).resolve()}
    for path in {sysconfig.get_paths().get("stdlib", ""), sysconfig.get_paths().get("purelib", "")}:
        if path:
            roots.add(Path(path).resolve())
    for path in site.getsitepackages():
        roots.add(Path(path).resolve())
    try:
        signals = _run_signals(package_dir=Path(args.package).resolve(), bars=bars, allowed_read_roots=tuple(roots))
    except BaseException as exc:  # subprocess boundary: return typed error instead of traceback contract drift
        reason = ReasonCode.ENGINE_FAILURE.value
        text = str(exc)
        for code in ReasonCode:
            if code.value in text:
                reason = code.value
                break
        stdout_write(json_dumps({"ok": False, "reason_code": reason, "message": text}, sort_keys=True))
        return 0
    stdout_write(json_dumps({"ok": True, "signals": signals}, sort_keys=True))
    return 0


def _apply_resource_limits() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (_MAX_CPU_SECONDS, _MAX_CPU_SECONDS + 1))
    except (ValueError, OSError, AttributeError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_AS, (_MAX_ADDRESS_SPACE_BYTES, _MAX_ADDRESS_SPACE_BYTES))
    except (ValueError, OSError, AttributeError):
        pass


if __name__ == "__main__":
    raise SystemExit(main())
