# Sentinel FastAPI guardrail service.
# This image serves the API only; command execution is kept for the separate executor image.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system sentinel \
    && useradd --system --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel

COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies

RUN pip install --no-cache-dir . \
    && chown -R sentinel:sentinel /app

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn", "sentinel.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
