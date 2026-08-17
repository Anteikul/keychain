FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KEYCHAIN_HOST=0.0.0.0 \
    KEYCHAIN_PORT=8080 \
    KEYCHAIN_DB=/data/keychain.db \
    KEYCHAIN_KEY=/data/.device-key

WORKDIR /app
RUN groupadd --system keychain && useradd --system --gid keychain --home-dir /app keychain \
    && mkdir -p /data && chown keychain:keychain /data

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py app.js static.css favicon.svg ./

USER keychain
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python3", "-c", "import os, ssl, urllib.request; tls=bool(os.environ.get('KEYCHAIN_TLS_CERT')); urllib.request.urlopen(('https' if tls else 'http')+'://127.0.0.1:8080/', context=ssl._create_unverified_context() if tls else None, timeout=2)"]

CMD ["python3", "app.py"]
