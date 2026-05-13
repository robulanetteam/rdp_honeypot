FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot.py rdp_protocol.py ntlm.py rdp_legacy.py ts_signing_key.py ./

# Непривилегированный пользователь
RUN useradd -r -s /usr/sbin/nologin honeypot && \
    mkdir -p /var/log/honeypot && \
    chown -R honeypot:honeypot /var/log/honeypot /app
USER honeypot

EXPOSE 3389
CMD ["python", "honeypot.py"]
