#!/bin/bash
# Замена systemd-таймера: запускает log_processor.py каждые 60 секунд.
# Запускается supervisord внутри контейнера.
while true; do
    python /app/log_processor.py 2>&1 || true
    sleep 60
done
