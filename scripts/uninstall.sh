#!/bin/bash
# Полное удаление honeypot с хоста.
# Путь установки: первый аргумент или переменная INSTALL_DIR (по умолчанию /srv/rdp-honeypot)
set -euo pipefail

INSTALL_DIR="${1:-${INSTALL_DIR:-/srv/rdp-honeypot}}"

systemctl disable --now rdp-honeypot-logs.timer 2>/dev/null || true
systemctl disable --now rdp-honeypot.service 2>/dev/null || true

rm -f /etc/systemd/system/rdp-honeypot.service \
      /etc/systemd/system/rdp-honeypot-logs.service \
      /etc/systemd/system/rdp-honeypot-logs.timer
systemctl daemon-reload

if [ -d "$INSTALL_DIR" ]; then
    cd "$INSTALL_DIR"
    if docker compose version >/dev/null 2>&1; then
        docker compose down -v || true
    else
        docker-compose down -v || true
    fi
fi

# Снимаем iptables-цепочку
iptables -D INPUT -p tcp --dport 3389 -m comment --comment "rdp-honeypot-ratelimit" -j RDPHONEY 2>/dev/null || true
iptables -F RDPHONEY 2>/dev/null || true
iptables -X RDPHONEY 2>/dev/null || true

echo "Удалено. Каталог $INSTALL_DIR оставлен — удалите вручную если нужно."
