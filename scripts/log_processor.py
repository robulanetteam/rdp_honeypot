#!/usr/bin/env python3
"""
RDP Honeypot log processor.

Парсит JSONL-логи honeypot.py:
  - data/logs/connections.jsonl   — события соединений
  - data/logs/credentials.jsonl  — захваченные учётные данные

Делает:
  * каждое N-е подключение от IP → публичный лог
  * credentials → приватный лог
  * классифицирует каждый IP: scanner / bruteforcer / accidental / unknown
    результат → data/logs/analytics.jsonl (пишется при изменении класса)

Запускается supervisord (log_loop.sh) раз в минуту.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from classifier import SessionInfo, IpAnalysis, classify_ip, correlate_subnet_scan

LOG_DIR      = Path(os.environ.get("HONEYPOT_LOG_DIR", "/var/log/honeypot"))
CONN_JSONL   = LOG_DIR / "connections.jsonl"
CRED_JSONL   = LOG_DIR / "credentials.jsonl"
ANALYTICS    = LOG_DIR / "analytics.jsonl"
STATE_FILE   = LOG_DIR / "state.json"

MIRROR_DIR   = Path(os.environ.get("MIRROR_DIR", "/srv/http/update"))
PUBLIC_LOG   = MIRROR_DIR / os.environ.get("PUBLIC_LOG_NAME", "rdp_honeypot.txt")
PRIVATE_LOG  = Path(os.environ.get("PRIVATE_LOG", "/var/log/rdp_honeypot_credentials.log"))

EVERY_N  = int(os.environ.get("PUBLIC_LOG_EVERY_N", "3"))
WINDOW   = timedelta(hours=int(os.environ.get("WINDOW_HOURS", "24")))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("rdp-honeypot")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> float:
    """ISO-8601 → POSIX float. Returns 0.0 on failure."""
    try:
        return datetime.fromisoformat(ts_str).timestamp()
    except (ValueError, TypeError, AttributeError):
        return 0.0


def load_state() -> dict[str, Any]:
    empty: dict[str, Any] = {
        "offsets": {}, "ip_attempts": {},
        "sessions": {}, "ip_creds": {}, "ip_class": {},
    }
    if not STATE_FILE.exists():
        return empty
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("state.json повреждён (%s), сбрасываем", exc)
        return empty


def save_state(state: dict[str, Any]) -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(STATE_FILE)


def prune_old(state: dict[str, Any], now: datetime) -> None:
    cutoff = (now - WINDOW).timestamp()

    # ip_attempts
    state["ip_attempts"] = {
        ip: [t for t in ts if t >= cutoff]
        for ip, ts in state.get("ip_attempts", {}).items()
        if any(t >= cutoff for t in ts)
    }
    # sessions
    state["sessions"] = {
        k: v for k, v in state.get("sessions", {}).items()
        if v.get("last_ts", 0) >= cutoff
    }
    # ip_class — прунить только IPs без активных сессий
    active_ips = {v["ip"] for v in state["sessions"].values()}
    state["ip_class"] = {
        ip: v for ip, v in state.get("ip_class", {}).items()
        if ip in active_ips
    }


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


def append_analytics(obj: dict) -> None:
    ANALYTICS.parent.mkdir(parents=True, exist_ok=True)
    with ANALYTICS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ── Session accumulation ──────────────────────────────────────────────────────

def _update_session(sessions: dict, ip: str, port: int, obj: dict) -> None:
    key = f"{ip}:{port}"
    stage = obj.get("stage", "")
    ts = _parse_ts(obj.get("timestamp", ""))

    if stage == "tcp_accept" or key not in sessions:
        sessions[key] = {
            "ip": ip, "port": port,
            "stages": [], "requested_protocols": 0,
            "cookie": "", "errors": [], "selected": None,
            "has_credentials": False,
            "channel_names": [], "client_build": 0,
            "first_ts": ts, "last_ts": ts,
        }

    sess = sessions[key]
    if stage and stage not in sess["stages"]:
        sess["stages"].append(stage)
    sess["last_ts"] = max(sess.get("last_ts", 0), ts)

    if stage == "x224_cr":
        proto = obj.get("requested_protocols", "0x0")
        sess["requested_protocols"] = (
            int(proto, 16) if isinstance(proto, str) else int(proto)
        )
        sess["cookie"] = obj.get("cookie") or ""
    elif stage == "x224_cc":
        sess["selected"] = obj.get("selected")
    elif stage == "exception":
        err = obj.get("error", "")
        if err and err not in sess["errors"]:
            sess["errors"].append(err)
    elif stage == "mcs_connect_initial":
        if not sess.get("channel_names"):  # keep first seen value per session
            sess["channel_names"] = obj.get("channel_names", [])
        if not sess.get("client_build"):
            sess["client_build"] = obj.get("client_build", 0)


# ── Main processors ───────────────────────────────────────────────────────────

def process_connections(state: dict[str, Any], now: datetime) -> int:
    offsets  = state.setdefault("offsets", {})
    sessions = state.setdefault("sessions", {})
    cutoff   = (now - WINDOW).timestamp()
    processed = 0

    for obj in iter_new_lines(CONN_JSONL, offsets):
        processed += 1
        ip   = obj.get("source_ip")
        port = obj.get("source_port")
        if not ip or not port:
            continue

        _update_session(sessions, ip, port, obj)

        if obj.get("stage") != "tcp_accept":
            continue

        attempts = state.setdefault("ip_attempts", {}).setdefault(ip, [])
        attempts.append(now.timestamp())
        count = sum(1 for t in attempts if t >= cutoff)

        if count % EVERY_N == 0:
            ts_str   = now.strftime("%Y-%m-%d %H:%M %z")
            hours    = int(WINDOW.total_seconds() / 3600)
            cls_info = state.get("ip_class", {}).get(ip, {})
            cls_tag  = cls_info.get("classification", "")
            cls_str  = f" | {cls_tag}" if cls_tag else ""
            line     = f"{ts_str} | {ip} | attempt #{count} in last {hours}h{cls_str}"
            append_public(line)
            log.info("Public log: %s", line)

    return processed


def process_credentials(state: dict[str, Any]) -> int:
    offsets  = state.setdefault("offsets", {})
    ip_creds = state.setdefault("ip_creds", {})
    sessions = state.setdefault("sessions", {})
    processed = 0

    for obj in iter_new_lines(CRED_JSONL, offsets):
        processed += 1
        src  = obj.get("source_ip", "?")
        via  = obj.get("captured_via", "?")
        user = obj.get("username", "")
        domain = obj.get("domain", "")
        workstation = obj.get("workstation", "")
        password = obj.get("password")
        hashcat  = obj.get("hashcat", "")
        ts = obj.get("timestamp", "?")

        ip_creds[src] = True
        for sess in sessions.values():
            if sess.get("ip") == src:
                sess["has_credentials"] = True

        if password:
            line = (
                f"{ts} | src={src} | via={via} | "
                f"domain={domain!r} user={user!r} password={password!r}"
            )
        else:
            ver  = obj.get("ntlm_version", "?")
            line = (
                f"{ts} | src={src} | via={via} | "
                f"domain={domain!r} user={user!r} workstation={workstation!r} "
                f"ntlm={ver} | hashcat={hashcat}"
            )
        append_private(line)
        log.info("Credential captured (src=%s via=%s user=%r %s)",
                 src, via, user, "PLAINTEXT" if password else "hash-only")

    return processed


def run_analytics(state: dict[str, Any], now: datetime) -> None:
    """Классифицировать каждый IP. Записать analytics.jsonl при изменении класса."""
    sessions_state = state.get("sessions", {})
    ip_creds = state.get("ip_creds", {})
    ip_class = state.setdefault("ip_class", {})

    # Группируем сессии по IP
    by_ip: dict[str, list[SessionInfo]] = {}
    for sess in sessions_state.values():
        ip = sess.get("ip", "")
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(
            SessionInfo(
                ip=ip,
                port=sess.get("port", 0),
                stages=sess.get("stages", []),
                requested_protocols=sess.get("requested_protocols", 0),
                cookie=sess.get("cookie", ""),
                errors=sess.get("errors", []),
                selected=sess.get("selected"),
                has_credentials=sess.get("has_credentials", False) or ip_creds.get(ip, False),
                first_ts=sess.get("first_ts", 0.0),
                last_ts=sess.get("last_ts", 0.0),
                channel_names=sess.get("channel_names", []),
                client_build=sess.get("client_build", 0),
            )
        )

    # Коррелируем /24: если ≥3 разных IP из одной подсети шлют TPKT-зонды в течение часа
    coordinated_ips = correlate_subnet_scan(by_ip)

    now_str = now.isoformat()
    for ip, sessions in by_ip.items():
        analysis = classify_ip(sessions)

        # Subnet correlation upgrade: конкретные IP-участники скоординированного скана
        if ip in coordinated_ips and "subnet_coordinated_scan" not in analysis.reasons:
            analysis.reasons = analysis.reasons + ["subnet_coordinated_scan"]
            if analysis.classification not in ("scanner", "bruteforcer"):
                analysis.classification = "scanner"
                analysis.confidence = "medium"

        prev         = ip_class.get(ip, {})
        prev_reasons = prev.get("reasons", [])
        changed      = (
            prev.get("classification") != analysis.classification
            or prev.get("confidence") != analysis.confidence
            or (
                "subnet_coordinated_scan" in analysis.reasons
                and "subnet_coordinated_scan" not in prev_reasons
            )
        )
        if changed:
            entry = {
                "timestamp":      now_str,
                "source_ip":      ip,
                "classification": analysis.classification,
                "confidence":     analysis.confidence,
                "reasons":        analysis.reasons,
                "cve_hints":      analysis.cve_hints,
                "sessions_total": analysis.sessions_total,
                "protocols_seen": analysis.protocols_seen,
                "has_credentials": analysis.has_credentials,
            }
            append_analytics(entry)
            log.info(
                "Classification %s → %s [%s] %s",
                ip, analysis.classification, analysis.confidence,
                ",".join(analysis.reasons),
            )
        ip_class[ip] = {
            "classification": analysis.classification,
            "confidence":     analysis.confidence,
            "reasons":        analysis.reasons,
            "sessions_total": analysis.sessions_total,
            "updated_ts":     now.timestamp(),
        }


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    if not LOG_DIR.exists():
        log.error("Каталог логов %s не существует", LOG_DIR)
        return 1

    state = load_state()
    now   = datetime.now(timezone.utc).astimezone()
    prune_old(state, now)

    n_cred = process_credentials(state)
    n_conn = process_connections(state, now)
    run_analytics(state, now)
    save_state(state)

    log.info("Обработано: connections=%d credentials=%d", n_conn, n_cred)
    return 0


if __name__ == "__main__":
    sys.exit(main())
