.PHONY: install audit test schemas openapi service-smoke demo verify-demo verify-sponsor-fixture goldens goldens-check

install:
	uv sync --frozen --extra dev

audit:
	uv run python scripts/check-verdict-path-imports.py

test:
	uv run --extra dev pytest -q

schemas:
	uv run redline export-schemas

openapi:
	uv run python scripts/export-service-openapi.py --out schemas/service-openapi.json

service-smoke:
	bash scripts/service-smoke.sh

demo:
	uv run redline make-demo

verify-demo:
	@set +e; \
	uv run redline check artifacts/demo/pass/receipt.json --package fixtures/demo_pack --rerun --json; \
	code=$$?; \
	if [ "$$code" -ne 10 ]; then echo "expected pass demo to exit 10 BASELINE_GENESIS, got $$code"; exit $$code; fi
	@set +e; \
	uv run redline check artifacts/demo/withheld/receipt.json --package fixtures/demo_pack --rerun --json; \
	code=$$?; \
	if [ "$$code" -ne 3 ]; then echo "expected withheld demo to exit 3 NEW_BLOCK_BREACH, got $$code"; exit $$code; fi

verify-sponsor-fixture:
	uv run python scripts/verify-sponsor-fixture.py

goldens: schemas openapi demo verify-demo

goldens-check: goldens verify-sponsor-fixture
	git diff --exit-code -- schemas artifacts/demo artifacts/sponsor
