from __future__ import annotations

import json
import time
import urllib.parse
import urllib.error
import urllib.request
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from redline.canonical import hash_file, hash_obj
from redline.io_safety import atomic_write_text, ensure_safe_output_dir, reject_unsafe_output_file
from redline.merkle import merkle_root
from redline.models import ExecutionEvidence, ExecutionIntent, ExecutionLedgerEntry, LedgerCheckpoint, Status
from redline.receipt import compute_ledger_checkpoint_hash
from redline.sponsor.bitget import BitgetCredentials, Transport, _is_official_bitget_base_url, bitget_auth_headers


PLACE_ORDER_PATH = "/api/v2/mix/order/place-order"
ORDER_DETAIL_PATH = "/api/v2/mix/order/detail"
CONTRACTS_PATH = "/api/v2/mix/market/contracts"
ACCOUNT_PATH = "/api/v2/mix/account/account"
DEFAULT_BASE_URL = "https://api.bitget.com"
DEFAULT_DEMO_SYMBOL = "BTCUSDT"
DEFAULT_PRODUCT_TYPE = "USDT-FUTURES"
DEFAULT_MARGIN_COIN = "USDT"
UNAPPROVED_APPROVAL_HASH = "sha256:unapproved"
GENESIS_HASH = "sha256:genesis"
EXECUTION_LINK_FIELDS = {"issuance_ledger_entry_hash", "issuance_checkpoint_hash", "approval_hash"}
DEMO_SYMBOL_ALLOWLIST = {
    "ADAUSDT",
    "BCHUSDT",
    "BNBUSDT",
    "BTCUSDT",
    "DOGEUSDT",
    "DOTUSDT",
    "ETHUSDT",
    "LINKUSDT",
    "LTCUSDT",
    "NEARUSDT",
    "PEPEUSDT",
    "SHIBUSDT",
    "SOLUSDT",
    "UNIUSDT",
    "XRPUSDT",
}


class ExecutionBlocked(Exception):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


class BitgetOrderPlacement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    client_oid: str
    bitget_order_id: str
    response_hash: str
    placed_at: str
    status_code: int


class BitgetExchangePreflightEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["redline.bitget.exchange_preflight.v1"] = "redline.bitget.exchange_preflight.v1"
    run_id: str
    receipt_hash: str
    client_oid: str
    checked_at: str
    symbol: str
    product_type: str
    margin_coin: str
    order_mode: Literal["demo", "mainnet"]
    paptrading: str | None = "1"
    ok: bool
    checks: list[dict[str, object]]
    contract_response_hash: str
    account_response_hash: str
    symbol_status: str | None = None
    min_trade_num: str | None = None
    min_trade_usdt: str | None = None
    price_place: str | None = None
    volume_place: str | None = None
    available: str | None = None
    preflight_hash: str


class BitgetOrderStatusEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["redline.bitget.order_status.v1"] = "redline.bitget.order_status.v1"
    run_id: str
    receipt_hash: str
    client_oid: str
    bitget_order_id: str | None = None
    queried_at: str
    symbol: str
    product_type: str
    order_mode: Literal["demo", "mainnet"]
    paptrading: str | None = "1"
    status: Literal["placed", "partially_filled", "filled", "cancelled", "rejected", "unknown_reconciliation_required"]
    raw_status: str | None = None
    response_hash: str
    status_code: int
    evidence_hash: str


class BitgetDemoExecutionAdapter:
    def __init__(
        self,
        *,
        credentials: BitgetCredentials,
        base_url: str = DEFAULT_BASE_URL,
        paptrading: str = "1",
        transport: Transport | None = None,
        timeout_seconds: float = 10.0,
        max_retries: int = 1,
        allow_mainnet_order: bool = False,
    ) -> None:
        self.credentials = credentials
        self.base_url = base_url.rstrip("/")
        self.paptrading = paptrading
        self.transport = transport
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(0, max_retries)
        self.allow_mainnet_order = allow_mainnet_order
        if paptrading not in {"0", "1"}:
            raise ExecutionBlocked("BITGET_PAPTRADING_INVALID", "REDLINE_BITGET_PAPTRADING must be 1 for demo or 0 for explicit mainnet")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if transport is None and not _is_official_bitget_base_url(self.base_url):
            raise ExecutionBlocked("BITGET_BASE_URL_UNTRUSTED", "live execution requires the official Bitget API host")

    def preflight_exchange(
        self,
        *,
        run_id: str,
        receipt_hash: str,
        intent: ExecutionIntent,
        client_oid: str,
    ) -> BitgetExchangePreflightEvidence:
        self._assert_mode(intent)
        checks: list[dict[str, object]] = []
        contract_response = self._request_json(method="GET", path=CONTRACTS_PATH, query={"productType": intent.product_type}, auth=False)
        account_response = self._request_json(
            method="GET",
            path=ACCOUNT_PATH,
            query={"symbol": intent.symbol, "productType": intent.product_type, "marginCoin": intent.margin_coin},
            auth=True,
        )
        contract = _find_contract(contract_response, symbol=intent.symbol)
        checks.append({"name": "symbol_exists", "ok": contract is not None})
        account_data = account_response.get("data") if isinstance(account_response, dict) else None
        account_ok = isinstance(account_data, dict)
        checks.append({"name": "account_readable", "ok": account_ok})
        if contract is not None:
            symbol_status = str(contract.get("symbolStatus") or contract.get("symbol_status") or "")
            if symbol_status:
                checks.append({"name": "symbol_status", "ok": symbol_status.lower() in {"normal", "listed", "tradable"}, "value": symbol_status})
            supported_margin = {str(item).upper() for item in contract.get("supportMarginCoins", []) if isinstance(item, str)}
            if supported_margin:
                checks.append({"name": "margin_coin_supported", "ok": intent.margin_coin.upper() in supported_margin})
            min_trade_num = _optional_decimal(contract.get("minTradeNum"))
            if min_trade_num is not None:
                checks.append({"name": "min_trade_num", "ok": _decimal(intent.size) >= min_trade_num, "value": str(contract.get("minTradeNum"))})
            checks.extend(_precision_checks(intent=intent, contract=contract))
            min_trade_usdt = _optional_decimal(contract.get("minTradeUSDT"))
            if min_trade_usdt is not None and intent.price is not None:
                checks.append({"name": "min_trade_usdt", "ok": _decimal(intent.price) * _decimal(intent.size) >= min_trade_usdt, "value": str(contract.get("minTradeUSDT"))})
        ok = all(bool(item.get("ok")) for item in checks)
        evidence = BitgetExchangePreflightEvidence(
            run_id=run_id,
            receipt_hash=receipt_hash,
            client_oid=client_oid,
            checked_at=_utc_now(),
            symbol=intent.symbol,
            product_type=intent.product_type,
            margin_coin=intent.margin_coin,
            order_mode="demo" if self.paptrading == "1" else "mainnet",
            paptrading=self.paptrading if self.paptrading == "1" else None,
            ok=ok,
            checks=checks,
            contract_response_hash=hash_obj(_redact_secrets(contract_response)),
            account_response_hash=hash_obj(_redact_secrets(account_response)),
            symbol_status=str(contract.get("symbolStatus") or "") if contract is not None else None,
            min_trade_num=str(contract.get("minTradeNum") or "") if contract is not None else None,
            min_trade_usdt=str(contract.get("minTradeUSDT") or "") if contract is not None else None,
            price_place=str(contract.get("pricePlace") or "") if contract is not None else None,
            volume_place=str(contract.get("volumePlace") or "") if contract is not None else None,
            available=str(account_data.get("available") or "") if isinstance(account_data, dict) else None,
            preflight_hash="sha256:" + "0" * 64,
        )
        return evidence.model_copy(update={"preflight_hash": _preflight_evidence_hash(evidence)})

    def place_order(
        self,
        *,
        intent: ExecutionIntent,
        receipt_hash: str,
        client_oid: str | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> BitgetOrderPlacement:
        self._assert_mode(intent)
        client_oid = client_oid or make_client_oid(receipt_hash=receipt_hash, intent=intent)
        payload = _order_payload(intent=intent, client_oid=client_oid)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {
            **bitget_auth_headers(credentials=self.credentials, method="POST", request_path=PLACE_ORDER_PATH, body=body),
            "Content-Type": "application/json",
            "locale": "en-US",
        }
        if self.paptrading == "1":
            headers["paptrading"] = "1"
        try:
            status_code, response_body = self._send(method="POST", path=PLACE_ORDER_PATH, headers=headers, body=body, cancelled=cancelled, retry_transport_errors=False)
        except ExecutionBlocked as exc:
            if exc.reason_code != "BITGET_TRANSPORT_ERROR":
                raise
            recovered = self.query_order_status(
                run_id="recovered",
                receipt_hash=receipt_hash,
                intent=intent,
                client_oid=client_oid,
                bitget_order_id=None,
            )
            if recovered.status == "unknown_reconciliation_required" or not recovered.bitget_order_id:
                raise ExecutionBlocked("EXCHANGE_RECONCILIATION_REQUIRED", "Bitget order placement timed out and clientOid query did not recover an order") from exc
            return BitgetOrderPlacement(
                client_oid=client_oid,
                bitget_order_id=recovered.bitget_order_id,
                response_hash=recovered.response_hash,
                placed_at=recovered.queried_at,
                status_code=recovered.status_code,
            )
        try:
            response = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutionBlocked("BITGET_RESPONSE_INVALID", "Bitget order response was not valid JSON") from exc
        if status_code >= 400:
            recovered = self._recover_duplicate_client_oid(
                response=response,
                receipt_hash=receipt_hash,
                intent=intent,
                client_oid=client_oid,
            )
            if recovered is not None:
                return recovered
            raise ExecutionBlocked("BITGET_ORDER_REJECTED", _bitget_failure_message(status_code=status_code, response=response))
        code = str(response.get("code", ""))
        if code != "00000":
            recovered = self._recover_duplicate_client_oid(
                response=response,
                receipt_hash=receipt_hash,
                intent=intent,
                client_oid=client_oid,
            )
            if recovered is not None:
                return recovered
            raise ExecutionBlocked("BITGET_ORDER_REJECTED", _bitget_failure_message(status_code=status_code, response=response))
        data = response.get("data")
        if not isinstance(data, dict):
            raise ExecutionBlocked("BITGET_RESPONSE_INVALID", "Bitget order response data was not an object")
        order_id = str(data.get("orderId") or "")
        if not order_id:
            raise ExecutionBlocked("BITGET_RESPONSE_INVALID", "Bitget order response did not include orderId")
        response_client_oid = str(data.get("clientOid") or client_oid)
        if response_client_oid != client_oid:
            raise ExecutionBlocked("BITGET_RESPONSE_INVALID", "Bitget order response clientOid mismatch")
        return BitgetOrderPlacement(
            client_oid=client_oid,
            bitget_order_id=order_id,
            response_hash=hash_obj(_redact_secrets(response)),
            placed_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            status_code=status_code,
        )

    def query_order_status(
        self,
        *,
        run_id: str,
        receipt_hash: str,
        intent: ExecutionIntent,
        client_oid: str,
        bitget_order_id: str | None,
    ) -> BitgetOrderStatusEvidence:
        self._assert_mode(intent)
        query = {
            "symbol": intent.symbol,
            "productType": intent.product_type,
            "clientOid": client_oid,
        }
        if bitget_order_id:
            query["orderId"] = bitget_order_id
        status_code = 0
        try:
            response = self._request_json(method="GET", path=ORDER_DETAIL_PATH, query=query, auth=True)
            status_code = int(response.get("_http_status", 0)) if isinstance(response, dict) else 0
        except ExecutionBlocked:
            response = {"code": "RECONCILIATION_FAILED", "data": {}, "msg": "order detail query failed"}
        data = response.get("data") if isinstance(response, dict) else None
        raw_status = None
        observed_order_id = bitget_order_id
        normalized_status: Literal["placed", "partially_filled", "filled", "cancelled", "rejected", "unknown_reconciliation_required"] = "unknown_reconciliation_required"
        if isinstance(data, dict):
            observed_order_id = str(data.get("orderId") or observed_order_id or "")
            raw_status = str(data.get("state") or data.get("status") or "")
            normalized_status = _normalize_order_status(raw_status)
        evidence = BitgetOrderStatusEvidence(
            run_id=run_id,
            receipt_hash=receipt_hash,
            client_oid=client_oid,
            bitget_order_id=observed_order_id or None,
            queried_at=_utc_now(),
            symbol=intent.symbol,
            product_type=intent.product_type,
            order_mode="demo" if self.paptrading == "1" else "mainnet",
            paptrading=self.paptrading if self.paptrading == "1" else None,
            status=normalized_status,
            raw_status=raw_status,
            response_hash=hash_obj(_redact_secrets(response)),
            status_code=status_code,
            evidence_hash="sha256:" + "0" * 64,
        )
        return evidence.model_copy(update={"evidence_hash": _order_status_evidence_hash(evidence)})

    def _request_json(self, *, method: str, path: str, query: dict[str, str], auth: bool) -> dict[str, object]:
        request_path = _path_with_query(path, query)
        body = b""
        headers = {"Content-Type": "application/json", "locale": "en-US"}
        if auth:
            headers.update(bitget_auth_headers(credentials=self.credentials, method=method, request_path=request_path, body=body))
        if self.paptrading == "1":
            headers["paptrading"] = "1"
        status_code, response_body = self._send(method=method, path=request_path, headers=headers, body=body, cancelled=None)
        try:
            response = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutionBlocked("BITGET_RESPONSE_INVALID", "Bitget read response was not valid JSON") from exc
        if not isinstance(response, dict):
            raise ExecutionBlocked("BITGET_RESPONSE_INVALID", "Bitget read response was not an object")
        response["_http_status"] = status_code
        if status_code >= 400 or str(response.get("code", "")) not in {"", "00000"}:
            raise ExecutionBlocked("BITGET_READ_REJECTED", _bitget_failure_message(status_code=status_code, response=response))
        return response

    def _send(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        cancelled: Callable[[], bool] | None,
        retry_transport_errors: bool = True,
    ) -> tuple[int, bytes]:
        url = self.base_url + path
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if cancelled is not None and cancelled():
                raise ExecutionBlocked("BITGET_ORDER_CANCELLED", "Bitget order request was cancelled")
            try:
                if self.transport is None:
                    status_code, response_body = _urllib_transport(method, url, headers, body, timeout_seconds=self.timeout_seconds)
                else:
                    status_code, response_body = self.transport(method, url, headers, body)
                if status_code >= 500 and attempt < self.max_retries:
                    time.sleep(min(0.25 * (attempt + 1), 1.0))
                    continue
                return status_code, response_body
            except Exception as exc:
                last_error = exc
                if attempt >= self.max_retries or not retry_transport_errors:
                    break
                time.sleep(min(0.25 * (attempt + 1), 1.0))
        assert last_error is not None
        raise ExecutionBlocked("BITGET_TRANSPORT_ERROR", type(last_error).__name__) from last_error

    def _assert_mode(self, intent: ExecutionIntent) -> None:
        if self.paptrading == "1":
            if not _is_demo_symbol(intent.symbol):
                raise ExecutionBlocked("BITGET_DEMO_SYMBOL_REQUIRED", "demo execution only allows demo symbols")
            return
        if self.allow_mainnet_order and intent.confirm_mainnet_order:
            return
        raise ExecutionBlocked("BITGET_MAINNET_DISABLED", "mainnet order placement is disabled")

    def _recover_duplicate_client_oid(
        self,
        *,
        response: object,
        receipt_hash: str,
        intent: ExecutionIntent,
        client_oid: str,
    ) -> BitgetOrderPlacement | None:
        if not _is_duplicate_client_oid_response(response):
            return None
        recovered = self.query_order_status(
            run_id="recovered",
            receipt_hash=receipt_hash,
            intent=intent,
            client_oid=client_oid,
            bitget_order_id=None,
        )
        if recovered.status == "unknown_reconciliation_required" or not recovered.bitget_order_id:
            raise ExecutionBlocked("EXCHANGE_RECONCILIATION_REQUIRED", "Bitget duplicate clientOid response did not recover an order")
        return BitgetOrderPlacement(
            client_oid=client_oid,
            bitget_order_id=recovered.bitget_order_id,
            response_hash=recovered.response_hash,
            placed_at=recovered.queried_at,
            status_code=recovered.status_code,
        )


def make_client_oid(*, receipt_hash: str, intent: ExecutionIntent) -> str:
    digest = hash_obj({"receipt_hash": receipt_hash, "intent": intent.model_dump(mode="json")}).removeprefix("sha256:")
    return "rl-" + digest[:29]


def make_showcase_client_oid(*, receipt_hash: str, intent: ExecutionIntent, attempt_id: str) -> str:
    digest = hash_obj(
        {
            "purpose": "redline-demo-showcase-order",
            "receipt_hash": receipt_hash,
            "intent": intent.model_dump(mode="json"),
            "attempt_id": attempt_id,
        }
    ).removeprefix("sha256:")
    return "rl-" + digest[:29]


def default_execution_intent(
    *,
    symbol: str = DEFAULT_DEMO_SYMBOL,
    product_type: str = DEFAULT_PRODUCT_TYPE,
    margin_coin: str | None = None,
    size: str = "0.0001",
    side: str = "buy",
    trade_side: str | None = "open",
    order_type: str = "market",
    force: str | None = None,
    price: str | None = None,
    confirm_mainnet_order: bool = False,
) -> ExecutionIntent:
    return ExecutionIntent(
        symbol=symbol,
        product_type=product_type,
        margin_coin=margin_coin or _default_margin_coin(symbol),
        size=size,
        side=side,  # type: ignore[arg-type]
        trade_side=trade_side,  # type: ignore[arg-type]
        order_type=order_type,  # type: ignore[arg-type]
        force=force,  # type: ignore[arg-type]
        price=price,
        confirm_mainnet_order=confirm_mainnet_order,
    )


def load_execution_evidence(path: Path) -> ExecutionEvidence:
    reject_unsafe_output_file(path)
    try:
        evidence = ExecutionEvidence.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ExecutionBlocked("EXECUTION_EVIDENCE_INVALID", "execution evidence artifact is invalid") from exc
    if evidence.artifact_hash != _execution_evidence_hash(evidence):
        raise ExecutionBlocked("EXECUTION_EVIDENCE_MISMATCH", "execution evidence artifact hash mismatch")
    return evidence


def load_exchange_preflight_evidence(path: Path) -> BitgetExchangePreflightEvidence:
    reject_unsafe_output_file(path)
    try:
        evidence = BitgetExchangePreflightEvidence.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ExecutionBlocked("EXCHANGE_PREFLIGHT_EVIDENCE_INVALID", "exchange preflight evidence artifact is invalid") from exc
    if evidence.preflight_hash != _preflight_evidence_hash(evidence):
        raise ExecutionBlocked("EXCHANGE_PREFLIGHT_EVIDENCE_MISMATCH", "exchange preflight evidence artifact hash mismatch")
    return evidence


def load_order_status_evidence(path: Path) -> BitgetOrderStatusEvidence:
    reject_unsafe_output_file(path)
    try:
        evidence = BitgetOrderStatusEvidence.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ExecutionBlocked("ORDER_STATUS_EVIDENCE_INVALID", "order status evidence artifact is invalid") from exc
    if evidence.evidence_hash != _order_status_evidence_hash(evidence):
        raise ExecutionBlocked("ORDER_STATUS_EVIDENCE_MISMATCH", "order status evidence artifact hash mismatch")
    return evidence


def write_exchange_preflight_evidence(path: Path, evidence: BitgetExchangePreflightEvidence) -> BitgetExchangePreflightEvidence:
    ensure_safe_output_dir(path.parent)
    reject_unsafe_output_file(path)
    if path.exists():
        existing = load_exchange_preflight_evidence(path)
        if existing.client_oid == evidence.client_oid and existing.receipt_hash == evidence.receipt_hash:
            return existing
        raise ExecutionBlocked("EXCHANGE_PREFLIGHT_EVIDENCE_MISMATCH", "different exchange preflight evidence already exists")
    atomic_write_text(path, evidence.model_dump_json(indent=2) + "\n")
    return evidence


def write_order_status_evidence(path: Path, evidence: BitgetOrderStatusEvidence) -> BitgetOrderStatusEvidence:
    ensure_safe_output_dir(path.parent)
    reject_unsafe_output_file(path)
    if path.exists():
        existing = load_order_status_evidence(path)
        if existing.client_oid == evidence.client_oid and existing.receipt_hash == evidence.receipt_hash:
            return existing
        raise ExecutionBlocked("ORDER_STATUS_EVIDENCE_MISMATCH", "different order status evidence already exists")
    atomic_write_text(path, evidence.model_dump_json(indent=2) + "\n")
    return evidence


def write_execution_evidence(
    *,
    run_id: str,
    out_dir: Path,
    receipt_hash: str,
    verdict: Status,
    intent: ExecutionIntent,
    order: BitgetOrderPlacement,
    order_mode: str = "demo",
    paptrading: str | None = "1",
    issuance_artifact_dir: Path | None = None,
    issuance_ledger_entry_hash: str | None = None,
    issuance_checkpoint_hash: str | None = None,
    approval_hash: str = UNAPPROVED_APPROVAL_HASH,
) -> ExecutionEvidence:
    ensure_safe_output_dir(out_dir)
    return write_execution_evidence_artifacts(
        run_id=run_id,
        evidence_path=out_dir / "execution-evidence.json",
        ledger_path=out_dir / "execution-ledger.jsonl",
        issuance_artifact_dir=issuance_artifact_dir or out_dir,
        issuance_ledger_entry_hash=issuance_ledger_entry_hash,
        issuance_checkpoint_hash=issuance_checkpoint_hash,
        approval_hash=approval_hash,
        receipt_hash=receipt_hash,
        verdict=verdict,
        intent=intent,
        order=order,
        order_mode=order_mode,
        paptrading=paptrading,
    )


def write_execution_evidence_artifacts(
    *,
    run_id: str,
    evidence_path: Path,
    ledger_path: Path,
    receipt_hash: str,
    verdict: Status,
    intent: ExecutionIntent,
    order: BitgetOrderPlacement,
    order_mode: str = "demo",
    paptrading: str | None = "1",
    issuance_artifact_dir: Path | None = None,
    issuance_ledger_entry_hash: str | None = None,
    issuance_checkpoint_hash: str | None = None,
    approval_hash: str = UNAPPROVED_APPROVAL_HASH,
) -> ExecutionEvidence:
    ensure_safe_output_dir(evidence_path.parent)
    ensure_safe_output_dir(ledger_path.parent)
    reject_unsafe_output_file(evidence_path)
    if evidence_path.exists():
        existing = load_execution_evidence(evidence_path)
        if existing.receipt_hash == receipt_hash and existing.client_oid == order.client_oid:
            return existing
        raise ExecutionBlocked("EXECUTION_EVIDENCE_MISMATCH", "run already has different execution evidence")

    ledger_entries = load_execution_ledger(ledger_path)
    if any(entry.receipt_hash == receipt_hash and entry.client_oid == order.client_oid for entry in ledger_entries):
        raise ExecutionBlocked("EXECUTION_EVIDENCE_MISSING", "execution ledger exists without evidence artifact")
    previous_entry_hash = ledger_entries[-1].entry_hash if ledger_entries else "sha256:genesis"
    issuance_link = _resolve_issuance_link(
        receipt_hash=receipt_hash,
        artifact_dir=issuance_artifact_dir or evidence_path.parent,
        issuance_ledger_entry_hash=issuance_ledger_entry_hash,
        issuance_checkpoint_hash=issuance_checkpoint_hash,
    )
    entry = ExecutionLedgerEntry(
        run_id=run_id,
        receipt_hash=receipt_hash,
        issuance_ledger_entry_hash=issuance_link["issuance_ledger_entry_hash"],
        issuance_checkpoint_hash=issuance_link["issuance_checkpoint_hash"],
        approval_hash=approval_hash,
        verdict=verdict,
        client_oid=order.client_oid,
        bitget_order_id=order.bitget_order_id,
        response_hash=order.response_hash,
        placed_at=order.placed_at,
        previous_entry_hash=previous_entry_hash,
        entry_hash="sha256:" + "0" * 64,
    )
    entry = entry.model_copy(update={"entry_hash": _execution_ledger_entry_hash(entry)})
    ledger_text = "".join(json.dumps(item.model_dump(mode="json"), sort_keys=True) + "\n" for item in [*ledger_entries, entry])
    reject_unsafe_output_file(ledger_path)
    atomic_write_text(ledger_path, ledger_text)

    evidence = ExecutionEvidence(
        run_id=run_id,
        receipt_hash=receipt_hash,
        issuance_ledger_entry_hash=issuance_link["issuance_ledger_entry_hash"],
        issuance_checkpoint_hash=issuance_link["issuance_checkpoint_hash"],
        approval_hash=approval_hash,
        verdict=verdict,
        client_oid=order.client_oid,
        bitget_order_id=order.bitget_order_id,
        response_hash=order.response_hash,
        placed_at=order.placed_at,
        symbol=intent.symbol,
        product_type=intent.product_type,
        order_mode=order_mode,  # type: ignore[arg-type]
        paptrading=paptrading,
        execution_ledger_entry_hash=entry.entry_hash,
        artifact_hash="sha256:" + "0" * 64,
    )
    evidence = evidence.model_copy(update={"artifact_hash": _execution_evidence_hash(evidence)})
    atomic_write_text(evidence_path, evidence.model_dump_json(indent=2) + "\n")
    return evidence


def _order_payload(*, intent: ExecutionIntent, client_oid: str) -> dict[str, str]:
    payload = {
        "symbol": intent.symbol,
        "productType": intent.product_type,
        "marginMode": intent.margin_mode,
        "marginCoin": intent.margin_coin,
        "size": intent.size,
        "side": intent.side,
        "orderType": intent.order_type,
        "clientOid": client_oid,
    }
    if intent.trade_side is not None:
        payload["tradeSide"] = intent.trade_side
    if intent.force is not None:
        payload["force"] = intent.force
    if intent.price is not None:
        payload["price"] = intent.price
    return payload


def execution_ledger_has_order(*, path: Path, receipt_hash: str, client_oid: str) -> bool:
    return any(entry.receipt_hash == receipt_hash and entry.client_oid == client_oid for entry in load_execution_ledger(path))


def load_execution_ledger(path: Path) -> list[ExecutionLedgerEntry]:
    if not path.exists():
        return []
    reject_unsafe_output_file(path)
    entries: list[ExecutionLedgerEntry] = []
    previous = "sha256:genesis"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ExecutionBlocked("EXECUTION_LEDGER_INVALID", "execution ledger is unreadable") from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = ExecutionLedgerEntry.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ExecutionBlocked("EXECUTION_LEDGER_INVALID", "execution ledger entry is invalid") from exc
        if entry.previous_entry_hash != previous or entry.entry_hash != _execution_ledger_entry_hash(entry):
            raise ExecutionBlocked("EXECUTION_LEDGER_MISMATCH", "execution ledger hash chain mismatch")
        entries.append(entry)
        previous = entry.entry_hash
    return entries


def _execution_ledger_entry_hash(entry: ExecutionLedgerEntry) -> str:
    payload = entry.model_dump(mode="json", exclude={"entry_hash"})
    for field in EXECUTION_LINK_FIELDS:
        if field not in entry.model_fields_set:
            payload.pop(field, None)
    return hash_obj(payload)


def _execution_evidence_hash(evidence: ExecutionEvidence) -> str:
    payload = evidence.model_dump(mode="json", exclude={"artifact_hash"})
    for field in EXECUTION_LINK_FIELDS:
        if field not in evidence.model_fields_set:
            payload.pop(field, None)
    return hash_obj(payload)


def _resolve_issuance_link(
    *,
    receipt_hash: str,
    artifact_dir: Path,
    issuance_ledger_entry_hash: str | None,
    issuance_checkpoint_hash: str | None,
) -> dict[str, str]:
    ledger_entry_hash = issuance_ledger_entry_hash or _issuance_ledger_entry_hash(artifact_dir / "issuance-ledger.jsonl", receipt_hash)
    checkpoint_hash = issuance_checkpoint_hash or _issuance_checkpoint_hash(artifact_dir / "issuance-ledger.checkpoint.json", artifact_dir / "issuance-ledger.jsonl", receipt_hash)
    return {
        "issuance_ledger_entry_hash": ledger_entry_hash,
        "issuance_checkpoint_hash": checkpoint_hash,
    }


def _issuance_ledger_entry_hash(path: Path, receipt_hash: str) -> str:
    if not path.exists():
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISSING", "issuance ledger is required for execution evidence")
    reject_unsafe_output_file(path)
    previous = GENESIS_HASH
    match: str | None = None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_INVALID", "issuance ledger is unreadable") from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_INVALID", "issuance ledger entry is invalid") from exc
        entry_hash = entry.get("entry_hash")
        expected = hash_obj({key: value for key, value in entry.items() if key != "entry_hash"})
        if not isinstance(entry_hash, str) or entry_hash != expected or entry.get("previous_entry_hash") != previous:
            raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISMATCH", "issuance ledger hash chain mismatch")
        if entry.get("receipt_hash") == receipt_hash:
            match = entry_hash
        previous = entry_hash
    if match is None:
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISSING", "issuance ledger entry for receipt is missing")
    return match


def _issuance_checkpoint_hash(path: Path, ledger_path: Path, receipt_hash: str) -> str:
    if not path.exists():
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISSING", "issuance checkpoint is required for execution evidence")
    reject_unsafe_output_file(path)
    try:
        checkpoint = LedgerCheckpoint.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_INVALID", "issuance checkpoint is invalid") from exc
    expected_hash = compute_ledger_checkpoint_hash(checkpoint)
    if checkpoint.checkpoint_hash != expected_hash:
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISMATCH", "issuance checkpoint hash mismatch")
    if "merkle_root" in checkpoint.model_fields_set and checkpoint.merkle_root != merkle_root(checkpoint.subject_receipt_hashes):
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISMATCH", "issuance checkpoint merkle root mismatch")
    if checkpoint.ledger_hash != hash_file(ledger_path):
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISMATCH", "issuance checkpoint ledger hash mismatch")
    if receipt_hash not in checkpoint.subject_receipt_hashes:
        raise ExecutionBlocked("EXECUTION_ISSUANCE_LINK_MISSING", "issuance checkpoint does not cover receipt")
    return checkpoint.checkpoint_hash


def _preflight_evidence_hash(evidence: BitgetExchangePreflightEvidence) -> str:
    return hash_obj(evidence.model_dump(mode="json", exclude={"preflight_hash"}))


def _order_status_evidence_hash(evidence: BitgetOrderStatusEvidence) -> str:
    return hash_obj(evidence.model_dump(mode="json", exclude={"evidence_hash"}))


def _path_with_query(path: str, query: dict[str, str]) -> str:
    filtered = {key: value for key, value in query.items() if value}
    if not filtered:
        return path
    return path + "?" + urllib.parse.urlencode(sorted(filtered.items()))


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _find_contract(response: dict[str, object], *, symbol: str) -> dict[str, object] | None:
    data = response.get("data")
    if not isinstance(data, list):
        return None
    for item in data:
        if isinstance(item, dict) and str(item.get("symbol") or "").upper() == symbol.upper():
            return item
    return None


def _decimal(value: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as exc:
        raise ExecutionBlocked("EXCHANGE_PREFLIGHT_INVALID_DECIMAL", "exchange preflight decimal field is invalid") from exc
    if not parsed.is_finite():
        raise ExecutionBlocked("EXCHANGE_PREFLIGHT_INVALID_DECIMAL", "exchange preflight decimal field is non-finite")
    return parsed


def _optional_decimal(value: object) -> Decimal | None:
    if value is None or str(value) == "":
        return None
    return _decimal(str(value))


def _decimal_places(value: str) -> int:
    parsed = _decimal(value)
    exponent = parsed.normalize().as_tuple().exponent
    return abs(exponent) if exponent < 0 else 0


def _precision_checks(*, intent: ExecutionIntent, contract: dict[str, object]) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    volume_place = contract.get("volumePlace")
    if volume_place not in {None, ""}:
        checks.append({"name": "size_precision", "ok": _decimal_places(intent.size) <= int(str(volume_place)), "value": str(volume_place)})
    price_place = contract.get("pricePlace")
    if price_place not in {None, ""} and intent.price is not None:
        checks.append({"name": "price_precision", "ok": _decimal_places(intent.price) <= int(str(price_place)), "value": str(price_place)})
    return checks


def _normalize_order_status(raw_status: str) -> Literal["placed", "partially_filled", "filled", "cancelled", "rejected", "unknown_reconciliation_required"]:
    value = raw_status.lower()
    if value in {"live", "new", "placed", "init", "open"}:
        return "placed"
    if value in {"partially_filled", "partial-fill", "partial_filled", "partfilled"}:
        return "partially_filled"
    if value in {"filled", "full-fill", "full_filled"}:
        return "filled"
    if value in {"cancelled", "canceled", "cancel"}:
        return "cancelled"
    if value in {"rejected", "fail", "failed"}:
        return "rejected"
    return "unknown_reconciliation_required"


def _is_demo_symbol(symbol: str) -> bool:
    return symbol.upper() in DEMO_SYMBOL_ALLOWLIST


def _default_margin_coin(symbol: str) -> str:
    normalized = symbol.upper()
    if normalized.endswith("USDC"):
        return "USDC"
    if normalized.endswith("USDT"):
        return "USDT"
    return DEFAULT_MARGIN_COIN


def _redact_secrets(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            if key.lower() in {"access-key", "access_key", "secret", "secret_key", "passphrase", "sign", "signature", "token"}:
                redacted[str(key)] = "***"
            else:
                redacted[str(key)] = _redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return value


def _is_duplicate_client_oid_response(response: object) -> bool:
    if not isinstance(response, dict):
        return False
    code = str(response.get("code") or "")
    message = str(response.get("msg") or response.get("message") or "").lower()
    return code == "40786" or "duplicate clientoid" in message or "duplicate client oid" in message


def _bitget_failure_message(*, status_code: int, response: object) -> str:
    if not isinstance(response, dict):
        return f"Bitget order request failed with HTTP {status_code}"
    code = str(response.get("code") or "")
    msg = str(response.get("msg") or "")
    detail = f"Bitget order request failed with HTTP {status_code}"
    if code:
        detail += f" code {code}"
    if msg:
        detail += f": {msg[:160]}"
    return detail


def _urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes, *, timeout_seconds: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body if method != "GET" else None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
