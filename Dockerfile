# SysGuard - Security Automation Tool
FROM python:3.11-slim as builder
WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim
RUN groupadd -r sysguard && useradd -r -g sysguard sysguard

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY sysguard.py .
COPY requirements.txt .

RUN mkdir -p /app/logs && chown -R sysguard:sysguard /app
USER sysguard
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/metrics')" || exit 1

CMD ["python", "sysguard.py"]
