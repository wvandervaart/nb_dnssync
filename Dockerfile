# Alpine base: the Debian slim image carried ~160 unpatched OS CVEs.

# Build stage: install dependencies into an isolated virtualenv
FROM python:3.12-alpine AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Runtime stage: no pip or build tooling
FROM python:3.12-alpine AS runtime

# Keep UID/GID 999 to match the old Debian image, so existing /data volumes stay writable.
RUN apk upgrade --no-cache \
    && (pip uninstall -y pip setuptools wheel || true) \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && (delgroup ping 2>/dev/null || true) \
    && addgroup -S -g 999 app \
    && adduser -S -u 999 -G app -h /app app

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
RUN rm -rf /opt/venv/bin/pip* /opt/venv/lib/python3.12/site-packages/pip*
COPY app/ ./app

RUN mkdir -p /data && chown -R app:app /app /data

USER app

ENV PATH="/opt/venv/bin:$PATH" \
    CONFIG_PATH=/app/config.yaml \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
