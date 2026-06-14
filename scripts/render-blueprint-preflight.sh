#!/usr/bin/env bash
set -euo pipefail

BLUEPRINT="${1:-render.yaml}"

if [[ ! -f "$BLUEPRINT" ]]; then
  echo "blueprint file not found: $BLUEPRINT" >&2
  exit 66
fi

if command -v render >/dev/null 2>&1; then
  render blueprints validate "$BLUEPRINT"
  exit 0
fi

if [[ -n "${RENDER_API_KEY:-}" && -n "${RENDER_OWNER_ID:-}" ]]; then
  curl -fsS \
    --request POST \
    --url "https://api.render.com/v1/blueprints/validate" \
    --header "accept: application/json" \
    --header "authorization: Bearer ${RENDER_API_KEY}" \
    --form "ownerId=${RENDER_OWNER_ID}" \
    --form "file=@${BLUEPRINT};type=application/x-yaml" \
    | python -m json.tool
  exit 0
fi

cat >&2 <<'EOF'
Render CLI and API credentials are unavailable; running local Render schema and
project deployment-shape validation. This is useful before dashboard setup, but
the Render API/CLI remains the authoritative preflight.
EOF

uv run python - "$BLUEPRINT" <<'PY'
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import jsonschema
import yaml


SCHEMA_URL = "https://render.com/schema/render.yaml.json"


def main() -> None:
    path = Path(sys.argv[1])
    blueprint = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(blueprint, dict):
        raise SystemExit("render.yaml must contain a mapping at the document root")

    with urllib.request.urlopen(SCHEMA_URL, timeout=30) as response:
        schema = json.loads(response.read().decode("utf-8"))
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(blueprint), key=lambda item: list(item.absolute_path))
    if errors:
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            print(f"{location}: {error.message}", file=sys.stderr)
        raise SystemExit(1)

    _assert_project_shape(blueprint)
    print(
        json.dumps(
            {
                "ok": True,
                "validator": "local-render-schema",
                "schema": SCHEMA_URL,
                "service": "playbook-redline-api",
                "database": "playbook-redline-db",
            },
            sort_keys=True,
        )
    )


def _assert_project_shape(blueprint: dict) -> None:
    services = blueprint.get("services")
    if not isinstance(services, list):
        raise SystemExit("render.yaml must define services")
    service = _find_by_name(services, "playbook-redline-api")
    if service.get("type") != "web":
        raise SystemExit("playbook-redline-api must be a public web service")
    if service.get("runtime") != "docker":
        raise SystemExit("playbook-redline-api must use runtime: docker")
    if service.get("dockerfilePath") != "./Dockerfile":
        raise SystemExit("playbook-redline-api must build ./Dockerfile")
    if service.get("healthCheckPath") != "/health":
        raise SystemExit("playbook-redline-api must use /health as health check")
    disk = service.get("disk") or {}
    if disk.get("mountPath") != "/data/redline-service":
        raise SystemExit("persistent disk must mount at /data/redline-service")

    env = _env_map(service.get("envVars"))
    _require_value(env, "REDLINE_SERVICE_ENV", "production")
    _require_value(env, "REDLINE_SERVICE_ROOT", "/data/redline-service")
    _require_value(env, "REDLINE_SERVICE_HOST", "0.0.0.0")
    _require_value(env, "REDLINE_SERVICE_METADATA_STORE", "postgres")
    _require_value(env, "REDLINE_SERVICE_ARTIFACT_STORE", "local")
    if not env.get("REDLINE_SERVICE_TOKEN", {}).get("generateValue"):
        raise SystemExit("REDLINE_SERVICE_TOKEN must use generateValue: true")
    if env.get("REDLINE_SERVICE_CORS_ORIGINS", {}).get("sync") is not False:
        raise SystemExit("REDLINE_SERVICE_CORS_ORIGINS must be sync: false")
    database_ref = env.get("REDLINE_DATABASE_URL", {}).get("fromDatabase") or {}
    if database_ref.get("name") != "playbook-redline-db" or database_ref.get("property") != "connectionString":
        raise SystemExit("REDLINE_DATABASE_URL must reference playbook-redline-db connectionString")

    databases = blueprint.get("databases")
    if not isinstance(databases, list):
        raise SystemExit("render.yaml must define databases")
    database = _find_by_name(databases, "playbook-redline-db")
    if database.get("databaseName") != "redline" or database.get("user") != "redline":
        raise SystemExit("playbook-redline-db must use redline databaseName and user")


def _find_by_name(items: list, name: str) -> dict:
    for item in items:
        if isinstance(item, dict) and item.get("name") == name:
            return item
    raise SystemExit(f"render.yaml is missing {name}")


def _env_map(items: object) -> dict[str, dict]:
    if not isinstance(items, list):
        raise SystemExit("playbook-redline-api must define envVars")
    env: dict[str, dict] = {}
    for item in items:
        if isinstance(item, dict) and "key" in item:
            env[str(item["key"])] = item
    return env


def _require_value(env: dict[str, dict], key: str, expected: str) -> None:
    actual = env.get(key, {}).get("value")
    if actual != expected:
        raise SystemExit(f"{key} must be {expected!r}, got {actual!r}")


if __name__ == "__main__":
    main()
PY
