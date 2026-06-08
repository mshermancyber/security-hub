FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for httpx/feedparser/sqlite/pytest-asyncio
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl tzdata && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app /app/app

RUN useradd --uid 10001 --no-create-home sechub && \
    mkdir -p /app/data && chown -R sechub:sechub /app
USER sechub

ENV SECHUB_DB=/app/data/sechub.sqlite

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
