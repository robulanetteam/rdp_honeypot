#!/usr/bin/env bash
# Быстрое обновление работающего honeypot после git push.
#
# Логика:
#   - Dockerfile / requirements.txt изменились → пересборка образа (30-60 сек даунтайм)
#   - classifier.py изменился                  → restart + --reclassify
#   - остальные .py                             → только restart (~3 сек даунтайм)
#   - ничего не изменилось                      → только restart (применить vol-монтирование)
set -euo pipefail

cd "$(dirname "$0")"

echo "==> git pull"
git pull

# Что изменилось относительно предыдущего коммита
CHANGED=$(git diff --name-only HEAD@{1} HEAD 2>/dev/null || echo "")

NEED_REBUILD=false
NEED_RECLASSIFY=false

for f in $CHANGED; do
    case "$f" in
        honeypot/Dockerfile|honeypot/requirements.txt)
            NEED_REBUILD=true
            ;;
        scripts/classifier.py)
            NEED_RECLASSIFY=true
            ;;
    esac
done

if $NEED_REBUILD; then
    echo "==> Dockerfile или requirements.txt изменились — пересборка образа"
    docker compose up -d --build --no-deps honeypot
else
    echo "==> Перезапуск контейнера (без пересборки)"
    docker compose restart honeypot
fi

# Ждём запуска supervisord
echo "==> Ждём старта supervisord..."
for i in $(seq 1 15); do
    if docker compose exec honeypot supervisorctl status > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

if $NEED_RECLASSIFY; then
    echo "==> classifier.py обновлён — переклассификация накопленных сессий"
    docker compose exec honeypot python /app/log_processor.py --reclassify
fi

echo ""
echo "✓ Обновление завершено."
docker compose exec honeypot supervisorctl status
