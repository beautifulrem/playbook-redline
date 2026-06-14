FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PATH="/app/.venv/bin:${PATH}" \
    REDLINE_SERVICE_ENV=production \
    REDLINE_SERVICE_ROOT=/data/redline-service \
    REDLINE_SERVICE_HOST=0.0.0.0 \
    REDLINE_SERVICE_PORT=8080

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.10.10 \
    && groupadd --system redline \
    && useradd --system --uid 10001 --gid redline --home-dir /app redline

COPY pyproject.toml uv.lock README.md SERVICE_API.md ./
COPY src ./src
COPY fixtures ./fixtures
COPY schemas ./schemas
COPY artifacts/demo ./artifacts/demo
COPY artifacts/sponsor ./artifacts/sponsor

RUN uv sync --frozen --no-dev \
    && mkdir -p /data/redline-service \
    && chown -R redline:redline /app /data/redline-service

USER redline

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "redline.service.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
