#!/usr/bin/env python3
"""
Экспорт актуального blocklist из state.json.

Форматы вывода (--format):
  plain     — один IP на строку (по умолчанию)
  json      — JSON-массив объектов
  mikrotik  — RouterOS /ip firewall address-list add ...
  csv       — IP,scope,block_until,classification,threat_days

Примеры:
  blocklist_export.py
  blocklist_export.py --min-scope 50 --format mikrotik --list-name RDP_HONEYPOT
  blocklist_export.py --format json --output /tmp/block.json
  blocklist_export.py --all            # включить уже истёкшие записи
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR    = Path(os.environ.get("HONEYPOT_LOG_DIR", "/var/log/honeypot"))
STATE_FILE = LOG_DIR / "state.json"


def load_history(state_path: Path) -> dict:
    try:
        data = json.loads(state_path.read_text())
        return data.get("ip_history", {})
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Ошибка чтения {state_path}: {exc}", file=sys.stderr)
        sys.exit(1)


def get_rows(
    history: dict,
    min_scope: int,
    include_expired: bool,
) -> list[dict]:
    now_ts = datetime.now(timezone.utc).timestamp()
    result = []

    for ip, hist in history.items():
        scope       = hist.get("scope", 0)
        block_until = hist.get("block_until")

        if scope < min_scope or not block_until:
            continue

        try:
            block_until_ts = datetime.fromisoformat(block_until).timestamp()
        except (ValueError, TypeError):
            continue

        expired = block_until_ts <= now_ts
        if expired and not include_expired:
            continue

        first_seen = hist.get("first_seen")
        last_seen  = hist.get("last_seen")

        result.append({
            "ip":             ip,
            "scope":          scope,
            "block_until":    block_until,
            "classification": hist.get("last_classification", "unknown"),
            "confidence":     hist.get("last_confidence", ""),
            "threat_days":    len(hist.get("threat_days", [])),
            "first_seen":     (
                datetime.fromtimestamp(first_seen, tz=timezone.utc).isoformat()
                if first_seen else None
            ),
            "last_seen": (
                datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat()
                if last_seen else None
            ),
            "expired":        expired,
        })

    result.sort(key=lambda x: (-x["scope"], x["ip"]))
    return result


def format_plain(rows: list[dict]) -> str:
    return "\n".join(r["ip"] for r in rows) + ("\n" if rows else "")


def format_json(rows: list[dict]) -> str:
    return json.dumps(rows, ensure_ascii=False, indent=2)


def format_mikrotik(rows: list[dict], list_name: str) -> str:
    lines = []
    for r in rows:
        comment = (
            f"scope={r['scope']} cls={r['classification']} "
            f"days={r['threat_days']} until={r['block_until'][:10]}"
        )
        lines.append(
            f'/ip firewall address-list add list="{list_name}" '
            f'address={r["ip"]} comment="{comment}"'
        )
    return "\n".join(lines) + ("\n" if lines else "")


def format_csv(rows: list[dict]) -> str:
    header = "ip,scope,block_until,classification,threat_days\n"
    body = "".join(
        f"{r['ip']},{r['scope']},{r['block_until']},{r['classification']},{r['threat_days']}\n"
        for r in rows
    )
    return header + body


def main() -> int:
    ap = argparse.ArgumentParser(description="RDP Honeypot blocklist exporter")
    ap.add_argument(
        "--state", default=str(STATE_FILE),
        help="Путь к state.json (по умолчанию: %(default)s)",
    )
    ap.add_argument(
        "--min-scope", "--min-score", type=int, default=30, dest="min_scope",
        help="Минимальный scope для включения в список (default: 30)",
    )
    ap.add_argument(
        "--format", choices=["plain", "json", "mikrotik", "csv"],
        default="plain", help="Формат вывода (default: plain)",
    )
    ap.add_argument(
        "--list-name", default="RDP_HONEYPOT",
        help="Имя address-list для MikroTik формата (default: RDP_HONEYPOT)",
    )
    ap.add_argument(
        "--output", "-o", default="-",
        help="Файл для записи (- = stdout, default)",
    )
    ap.add_argument(
        "--all", action="store_true", dest="include_expired",
        help="Включить истёкшие записи",
    )
    args = ap.parse_args()

    history = load_history(Path(args.state))
    rows    = get_rows(history, args.min_scope, args.include_expired)

    if args.format == "plain":
        out = format_plain(rows)
    elif args.format == "json":
        out = format_json(rows)
    elif args.format == "mikrotik":
        out = format_mikrotik(rows, args.list_name)
    elif args.format == "csv":
        out = format_csv(rows)
    else:
        out = format_plain(rows)

    if args.output == "-":
        sys.stdout.write(out)
    else:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Записано: {len(rows)} IP → {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
