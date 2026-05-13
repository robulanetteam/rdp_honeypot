#!/bin/bash
# Установка RDP honeypot на хост.
# - Создаёт /srv/rdp-honeypot/ из текущего каталога
# - Устанавливает systemd-юниты
# - Применяет iptables rate-limit для входящего TCP/3389
#
# Запускать от root.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR=/srv/rdp-honeypot
RATE_LIMIT_PER_MIN="${RATE_LIMIT_PER_MIN:-5}"

echo "[*] Проверка зависимостей..."
for bin in docker iptables ip6tables; do
    command -v "$bin" >/dev/null || { echo "ERROR: нет $bin"; exit 1; }
done
# docker compose v2 vs docker-compose v1
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null; then
    DC="docker-compose"
else
    echo "ERROR: нужен docker compose (v2) или docker-compose (v1)"
    exit 1
fi

echo "[*] Копирование в $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$REPO_DIR"/* "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/data/logs" "$INSTALL_DIR/data/replays"

if [ ! -f "$INSTALL_DIR/.env" ]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
fi

echo "[*] Установка systemd-юнитов..."
install -m 644 "$INSTALL_DIR/systemd/rdp-honeypot.service" /etc/systemd/system/
install -m 644 "$INSTALL_DIR/systemd/rdp-honeypot-logs.service" /etc/systemd/system/
install -m 644 "$INSTALL_DIR/systemd/rdp-honeypot-logs.timer" /etc/systemd/system/
systemctl daemon-reload

echo "[*] iptables rate-limit для входящего 3389/tcp ($RATE_LIMIT_PER_MIN/мин на IP)..."
# Очищаем старые правила honeypot (если переустановка)
iptables -D INPUT -p tcp --dport 3389 -m comment --comment "rdp-honeypot-ratelimit" -j RDPHONEY 2>/dev/null || true
iptables -F RDPHONEY 2>/dev/null || true
iptables -X RDPHONEY 2>/dev/null || true

iptables -N RDPHONEY
iptables -A RDPHONEY -m state --state NEW -m recent --set --name RDPHONEY --rsource
iptables -A RDPHONEY -m state --state NEW -m recent --update --seconds 60 \
    --hitcount $((RATE_LIMIT_PER_MIN + 1)) --name RDPHONEY --rsource -j DROP
iptables -A RDPHONEY -j ACCEPT
iptables -I INPUT -p tcp --dport 3389 -m comment --comment "rdp-honeypot-ratelimit" -j RDPHONEY

# Сохраняем правила (Debian/Ubuntu netfilter-persistent ИЛИ просто dump в файл)
if command -v netfilter-persistent >/dev/null; then
    netfilter-persistent save
elif command -v iptables-save >/dev/null; then
    iptables-save > /etc/iptables.rules.rdp-honeypot
    echo "    -> Правила сохранены в /etc/iptables.rules.rdp-honeypot"
    echo "    -> Добавьте 'iptables-restore < /etc/iptables.rules.rdp-honeypot' в startup"
fi

echo "[*] Сборка Docker-образов..."
cd "$INSTALL_DIR"
$DC build

echo "[*] Запуск..."
systemctl enable --now rdp-honeypot.service
systemctl enable --now rdp-honeypot-logs.timer

echo
echo "===== УСТАНОВЛЕНО ====="
echo "Каталог: $INSTALL_DIR"
echo "Статус:  systemctl status rdp-honeypot"
echo "Логи:    journalctl -u rdp-honeypot -f"
echo "Публичный лог:  /srv/http/update/rdp_honeypot.txt"
echo "Приватный лог:  /var/log/rdp_honeypot_credentials.log (chmod 0600)"
echo
echo "Проверка iptables: iptables -L RDPHONEY -v"
