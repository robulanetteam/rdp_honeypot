FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# supervisor — менеджер процессов (honeypot + log_processor)
RUN apt-get update && \
    apt-get install -y --no-install-recommends supervisor ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context = корень репозитория (context: . в docker-compose.yml)
COPY honeypot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot/honeypot.py honeypot/rdp_protocol.py honeypot/ntlm.py \
     honeypot/rdp_legacy.py honeypot/ts_signing_key.py ./
COPY scripts/log_processor.py ./log_processor.py
COPY scripts/classifier.py ./classifier.py
COPY scripts/blocklist_export.py ./blocklist_export.py
COPY honeypot/log_loop.sh ./log_loop.sh
COPY honeypot/supervisord.conf ./supervisord.conf

RUN chmod +x /app/log_loop.sh && \
    mkdir -p /data/logs /data/public /data/private /data/geoip /var/log/supervisor

EXPOSE 3389
CMD ["/usr/bin/supervisord", "-n", "-c", "/app/supervisord.conf"]
