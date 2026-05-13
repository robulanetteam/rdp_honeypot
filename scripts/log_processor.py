#!/usr/bin/env python3
"""
RDP Honeypot log processor.

Парсит JSONL-логи самописного listener (honeypot.py):
  - data/logs/connections.jsonl
  - data/logs/credentials.jsonl

Делает:
  * считает уникальные попытки от каждого IP за окно WINDOW_HOURS (по умолч. 24ч)
  * каждое N-е (по умолч. 3-е) подключение → публичный лог на зеркале
  * пары login/password (NetNTLM hash) → приватный лог /var/log/...

Запускается systemd-таймером раз в минуту. Состояние — state.json рядом с
JSONL-логами; учитываются offset'ы файлов для идемпотентности.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

LOG_DIR = Path(os.environ.get("HONEYPOT_LOG_DIR", "/srv/rdp-honeypot/data/logs"))
CONN_JSONL = LOG_DIR / "connections.jsonl"
CRED_JSONL = LOG_DIR / "credentials.jsonl"
STATE_FILE = LOG_DIR / "state.json"

MIRROR_DIR = Path(os.environ.get("MIRROR_DIR", "/srv/http/update"))
PUBLIC_LOG = MIRROR_DIR / os.environ.get("PUBLIC_LOG_NAME", "rdp_honeypot.txt")
PRIVATE_LOG = Path(
    os.environ.get("PRIVATE_LOG", "/var/log/rdp_honeypot_credentials.log")
)

EVERY_N = int(os.environ.get("PUBLIC_LOG_EVERY_N", "3"))
WINDOW = timedelta(hours=int(os.environ.get("WINDOW_HOURS", "24")))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("rdp-honeypot")


def load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"offsets": {}, "ip_attempts": {}}
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("state.json повреждён (%s), сбрасываем", exc)
        return {"offsets": {}, "ip_attempts": {}}


def save_state(state: dict[str, Any]) -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(STATE_FILE)


def prune_ip_attempts(state: dict[str, Any], now: datetime) -> None:
    cutoff = (now - WINDOW).timestamp()
    new: dict[str, list[float]] = {}
    for ip, timestamps in state.get("ip_attempts", {}).items():
        recent = [t for t in timestamps if t >= cutoff]
        if recent:
            new[ip] = recent
    state["ip_attempts"] = new


def iter_new_lines(path: Path, offsets: dict[str, int]):
    if not path.exists():
        return
    key = str(path)
    start = offsets.get(key, 0)
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size < start:
        start = 0  # logrotate
    if size == start:
        return
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(start)
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except json.JSONDecodeError:
                    continue
            offsets[key] = f.tell()
    except OSError as exc:
        log.warning("Не удалось прочитать %s: %s", path, exc)


def append_public(line: str) -> None:
    PUBLIC_LOG.parent.mkdir(parents=True, exist_ok=True)
    with PUBLIC_LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def append_private(line: str) -> None:
    PRIVATE_LOG.parent.mkdir(parents=True, exist_ok=True)
    if not PRIVATE_LOG.exists():
        PRIVATE_LOG.touch(mode=0o600)
    with PRIVATE_LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    try:
        PRIVATE_LOG.chmod(0o600)
    except OSError:
        pass


def process_connections(state: dict[str, Any], now: datetime) -> int:
    """Каждое N-е подключение от одного IP → публичный лог."""
    offsets = state.setdefault("offsets", {})
    cutoff = (now - WINDOW).timestamp()
    processed = 0

    for obj in iter_new_lines(CONN_JSONL, offsets):
        processed += 1
        # Учитываем ТОЛЬКО факт принятого TCP/X.224 — не каждую стадию,
        # чтобы один клиент не давал нам 5 событий за одно соединение.
        if obj.get("stage") not in ("tcp_accept",):
            continue
        src = obj.get("source_ip")
        if not src:
            continue
        attempts = state.setdefault("ip_attempts", {}).setdefault(src, [])
        attempts.append(now.timestamp())
        count = sum(1 for t in attempts if t >= cutoff)

        if count % EVERY_N == 0:
            ts = now.strftime("%Y-%m-%d %H:%M:%S %z")
            hours = int(WINDOW.total_seconds() / 3600)
            line = f"{ts} | {src} | attempt #{count} in last {hours}h"
            append_public(line)
            log.info("Public log: %s", line)

    return processed


def process_credentials(state: dict[str, Any]) -> int:
    """Все credential events → приватный лог."""
    offsets = state.setdefault("offsets", {})
    processed = 0
    for obj in iter_new_lines(CRED_JSONL, offsets):
        processed += 1
        ts = obj.get("timestamp", "?")
        src = obj.get("source_ip", "?")
        via = obj.get("captured_via", "?")
        user = obj.get("username", "")
        domain = obj.get("domain", "")
        workstation = obj.get("workstation", "")
        password = obj.get("password")
        hashcat = obj.get("hashcat", "")
        if password:
            line = (
                f"{ts} | src={src} | via={via} | "
                f"domain={domain!r} user={user!r} password={password!r}"
            )
        else:
            ver = obj.get("ntlm_version", "?")
            line = (
                f"{ts} | src={src} | via={via} | "
                f"domain={domain!r} user={user!r} workstation={workstation!r} "
                f"ntlm={ver} | hashcat={hashcat}"
            )
        append_private(line)
        log.info("Credential captured (src=%s via=%s user=%r %s)",
                 src, via, user, "PLAINTEXT" if password else "hash-only")
    return processed


def main() -> int:
    if not LOG_DIR.exists():
        log.error("Каталог логов %s не существует", LOG_DIR)
        return 1
    state = load_state()
    now = datetime.now(timezone.utc).astimezone()
    prune_ip_attempts(state, now)

    n_conn = process_connections(state, now)
    n_cred = process_credentials(state)
    save_state(state)

    log.info("Обработано: connections=%d credentials=%d", n_conn, n_cred)
    return 0


if __name__ == "__main__":
    sys.exit(main())
