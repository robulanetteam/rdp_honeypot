#!/usr/bin/env bash
# Скачать GeoLite2-City.mmdb и GeoLite2-ASN.mmdb с MaxMind.
#
# Требует: MAXMIND_LICENSE_KEY в окружении или .env файле.
# Зарегистрируйтесь бесплатно: https://www.maxmind.com/en/geolite2/signup
#
# Использование:
#   MAXMIND_LICENSE_KEY=ваш_ключ ./scripts/download_geoip.sh
#   # или добавьте MAXMIND_LICENSE_KEY= в .env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Загружаем .env если ключ не задан в окружении
if [[ -z "${MAXMIND_LICENSE_KEY:-}" && -f "$REPO_ROOT/.env" ]]; then
    # shellcheck disable=SC1091
    set -a; source "$REPO_ROOT/.env"; set +a
fi

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
    echo "Ошибка: задайте MAXMIND_LICENSE_KEY"
    echo "Зарегистрируйтесь бесплатно: https://www.maxmind.com/en/geolite2/signup"
    exit 1
fi

DEST="$REPO_ROOT/data/geoip"
mkdir -p "$DEST"

BASE_URL="https://download.maxmind.com/app/geoip_download"

for DB in GeoLite2-City GeoLite2-ASN; do
    echo "==> Скачиваем $DB..."
    TMP="$(mktemp -d)"
    curl -fsSL \
        "${BASE_URL}?edition_id=${DB}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
        -o "$TMP/${DB}.tar.gz"
    tar -xzf "$TMP/${DB}.tar.gz" -C "$TMP"
    MMDB="$(find "$TMP" -name "${DB}.mmdb" | head -1)"
    if [[ -z "$MMDB" ]]; then
        echo "Ошибка: ${DB}.mmdb не найден в архиве"
        rm -rf "$TMP"
        exit 1
    fi
    cp "$MMDB" "$DEST/${DB}.mmdb"
    rm -rf "$TMP"
    echo "   OK → $DEST/${DB}.mmdb"
done

echo ""
echo "✓ GeoIP базы обновлены. Перезапустите контейнер:"
echo "  docker compose restart honeypot"
