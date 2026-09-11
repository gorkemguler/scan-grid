# ScanGrid - one image, either role via SCANGRID_ROLE.
# Multi-arch: linux/amd64 + linux/arm64 (Raspberry Pi 4).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SCANGRID_DATA_DIR=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --system --uid 10001 scangrid && mkdir -p /data && chown scangrid /data
USER scangrid
VOLUME ["/data"]
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://localhost:8090/healthz || exit 1
CMD ["scangrid", "orchestrator"]
