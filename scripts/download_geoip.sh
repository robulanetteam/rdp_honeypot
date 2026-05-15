#!/usr/bin/env bash
# Скачать GeoLite2-City.mmdb и GeoLite2-ASN.mmdb с зеркала update.edvels.com.
#
# Зеркало автоматически обновляет базы с MaxMind — ключ хранится только на сервере зеркала.
#
# Использование:
#   ./scripts/download_geoip.sh
#   # или явно указать другой URL зеркала:
#   GEOIP_MIRROR=https://update.edvels.com ./scripts/download_geoip.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
DEST="$REPO_ROOT/data/geoip"
MIRROR="${GEOIP_MIRROR:-https://update.edvels.com}"

mkdir -p "$DEST"

for DB in GeoLite2-City GeoLite2-ASN; do
    echo "==> Скачиваем ${DB}.mmdb с ${MIRROR}..."
    curl -fsSL --progress-bar \
        "${MIRROR}/${DB}.mmdb" \
        -o "$DEST/${DB}.mmdb"
    SIZE=$(stat -c%s "$DEST/${DB}.mmdb" 2>/dev/null || stat -f%z "$DEST/${DB}.mmdb")
    echo "   OK → $DEST/${DB}.mmdb (${SIZE} bytes)"
done

echo ""
echo "✓ GeoIP базы обновлены. Перезапустите контейнер если он уже запущен:"
echo "  docker compose restart honeypot"

echo ""
echo "✓ GeoIP базы обновлены. Перезапустите контейнер:"
echo "  docker compose restart honeypot"
