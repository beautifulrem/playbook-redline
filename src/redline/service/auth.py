from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from time import time
from typing import Iterable


READ_ONLY = "read-only"
RELEASE_WRITE = "release-write"
EXECUTE_DEMO = "execute-demo"
ADMIN = "admin"
SESSION_COOKIE_NAME = "redline_session"

VALID_SCOPES = frozenset({READ_ONLY, RELEASE_WRITE, EXECUTE_DEMO, ADMIN})
VALID_ROLES = frozenset({"author", "reviewer", "release_manager", "admin"})
VALID_AUTH_METHODS = frozenset({"service_token", "github_oauth", "dev_session"})


@dataclass(frozen=True)
class AuthPrincipal:
    principal_id: str
    role: str
    scopes: frozenset[str]
    token_label: str = "primary"
    auth_method: str = "service_token"
    subject: str | None = None
    display_name: str | None = None
    email: str | None = None

    def has_scope(self, required: str) -> bool:
        return ADMIN in self.scopes or required in self.scopes

    def public_dict(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "role": self.role,
            "scopes": sorted(self.scopes),
            "token_label": self.token_label,
            "auth_method": self.auth_method,
            "subject": self.subject,
            "display_name": self.display_name,
            "email": self.email,
        }


@dataclass(frozen=True)
class ServiceToken:
    token: str
    principal: AuthPrincipal


def default_service_token(token: str) -> ServiceToken:
    return ServiceToken(
        token=token,
        principal=AuthPrincipal(
            principal_id="service-token",
            role="admin",
            scopes=frozenset({READ_ONLY, RELEASE_WRITE, EXECUTE_DEMO, ADMIN}),
            auth_method="service_token",
            subject="service-token",
        ),
    )


def parse_service_tokens(raw: str | None, *, fallback_token: str) -> tuple[ServiceToken, ...]:
    if raw is None or not raw.strip():
        return (default_service_token(fallback_token),)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("REDLINE_SERVICE_TOKENS must be a JSON array") from exc
    if not isinstance(payload, list) or not payload:
        raise ValueError("REDLINE_SERVICE_TOKENS must be a non-empty JSON array")
    return tuple(_service_token_from_json(item, index=index) for index, item in enumerate(payload))


def _service_token_from_json(item: object, *, index: int) -> ServiceToken:
    if not isinstance(item, dict):
        raise ValueError("REDLINE_SERVICE_TOKENS entries must be objects")
    token = str(item.get("token") or "")
    principal_id = str(item.get("principal_id") or item.get("user_id") or "")
    role = str(item.get("role") or "")
    scopes = item.get("scopes")
    label = str(item.get("label") or f"token-{index}")
    if not token or not principal_id:
        raise ValueError("REDLINE_SERVICE_TOKENS entries require token and principal_id")
    if role not in VALID_ROLES:
        raise ValueError(f"REDLINE_SERVICE_TOKENS role must be one of {sorted(VALID_ROLES)}")
    parsed_scopes = _parse_scopes(scopes) if scopes is not None else _default_scopes_for_role(role)
    return ServiceToken(
        token=token,
        principal=AuthPrincipal(
            principal_id=principal_id,
            role=role,
            scopes=parsed_scopes,
            token_label=label,
            auth_method="service_token",
            subject=principal_id,
            display_name=str(item.get("display_name") or principal_id),
            email=str(item["email"]) if item.get("email") else None,
        ),
    )


def _parse_scopes(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("REDLINE_SERVICE_TOKENS scopes must be a non-empty array")
    scopes = frozenset(str(item) for item in value)
    unknown = scopes - VALID_SCOPES
    if unknown:
        raise ValueError(f"REDLINE_SERVICE_TOKENS scopes are invalid: {sorted(unknown)}")
    return scopes


def _default_scopes_for_role(role: str) -> frozenset[str]:
    if role == "admin":
        return frozenset({READ_ONLY, RELEASE_WRITE, EXECUTE_DEMO, ADMIN})
    if role == "release_manager":
        return frozenset({READ_ONLY, RELEASE_WRITE, EXECUTE_DEMO})
    if role in {"author", "reviewer"}:
        return frozenset({READ_ONLY, RELEASE_WRITE})
    raise ValueError(f"unsupported role: {role}")


def token_lengths(tokens: Iterable[ServiceToken]) -> list[int]:
    return [len(item.token) for item in tokens]


def principal_from_auth_users(raw_users: str | None, *, login: str, auth_method: str = "dev_session") -> AuthPrincipal | None:
    if not raw_users or not raw_users.strip():
        return None
    try:
        payload = json.loads(raw_users)
    except json.JSONDecodeError as exc:
        raise ValueError("REDLINE_AUTH_USERS must be a JSON array") from exc
    if not isinstance(payload, list):
        raise ValueError("REDLINE_AUTH_USERS must be a JSON array")
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("REDLINE_AUTH_USERS entries must be objects")
        github_login = str(item.get("github_login") or item.get("login") or "")
        if github_login != login:
            continue
        role = str(item.get("role") or "reviewer")
        if role not in VALID_ROLES:
            raise ValueError(f"REDLINE_AUTH_USERS role must be one of {sorted(VALID_ROLES)}")
        scopes = _parse_scopes(item.get("scopes")) if item.get("scopes") is not None else _default_scopes_for_role(role)
        return AuthPrincipal(
            principal_id=str(item.get("principal_id") or f"github:{login}"),
            role=role,
            scopes=scopes,
            token_label="session",
            auth_method=auth_method,
            subject=login,
            display_name=str(item.get("display_name") or login),
            email=str(item["email"]) if item.get("email") else None,
        )
    return None


def dev_principal(*, raw_users: str | None, configured_user: str | None, requested_login: str | None = None) -> AuthPrincipal:
    login = requested_login or configured_user or "dev-reviewer"
    if configured_user and configured_user.strip().startswith("{"):
        try:
            payload = json.loads(configured_user)
        except json.JSONDecodeError as exc:
            raise ValueError("REDLINE_DEV_AUTH_USER JSON is invalid") from exc
        if not isinstance(payload, dict):
            raise ValueError("REDLINE_DEV_AUTH_USER JSON must be an object")
        login = requested_login or str(payload.get("github_login") or payload.get("login") or payload.get("subject") or "dev-reviewer")
        raw_users = json.dumps([payload])
    mapped = principal_from_auth_users(raw_users, login=login, auth_method="dev_session")
    if mapped is not None:
        return mapped
    return AuthPrincipal(
        principal_id=f"dev:{login}",
        role="release_manager",
        scopes=frozenset({READ_ONLY, RELEASE_WRITE, EXECUTE_DEMO}),
        token_label="session",
        auth_method="dev_session",
        subject=login,
        display_name=login,
    )


def make_session_cookie(principal: AuthPrincipal, *, secret: str, ttl_seconds: int = 8 * 60 * 60) -> str:
    now = int(time())
    payload = {
        **principal.public_dict(),
        "iat": now,
        "exp": now + ttl_seconds,
    }
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    return body + "." + sig


def principal_from_session_cookie(cookie: str, *, secret: str) -> AuthPrincipal | None:
    try:
        body, sig = cookie.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(_pad_b64(body)).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if int(payload.get("exp") or 0) < int(time()):
        return None
    role = str(payload.get("role") or "")
    auth_method = str(payload.get("auth_method") or "")
    scopes = frozenset(str(item) for item in payload.get("scopes") or [])
    if role not in VALID_ROLES or auth_method not in VALID_AUTH_METHODS or not scopes or scopes - VALID_SCOPES:
        return None
    return AuthPrincipal(
        principal_id=str(payload.get("principal_id") or ""),
        role=role,
        scopes=scopes,
        token_label=str(payload.get("token_label") or "session"),
        auth_method=auth_method,
        subject=str(payload["subject"]) if payload.get("subject") else None,
        display_name=str(payload["display_name"]) if payload.get("display_name") else None,
        email=str(payload["email"]) if payload.get("email") else None,
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _pad_b64(value: str) -> bytes:
    return (value + "=" * (-len(value) % 4)).encode("ascii")
