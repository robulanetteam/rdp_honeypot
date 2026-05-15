"""
RDP Honeypot — классификатор подключений.

Категории:
  scanner      — автоматический сканер/разведчик (nmap, masscan, zgrab, Shodan...)
  bruteforcer  — подбор паролей (дошёл до legacy RDP или получил учётные данные)
  accidental   — разовый клиент без признаков злоумысла
  unknown      — недостаточно данных для уверенной классификации

Сигналы:

  Scanner:
    +5  cookie содержит имя известного сканера (nmap, masscan, zgrab...)
    +3  TPKT exception — прямой TLS-зонд (байт 0x16), не RDP
    +3  HYBRID_EX bit (0x08) в requested_protocols — признак автоматизированного клиента
    +2  ≥3 соединений с одного IP за <120 сек
    +1  >2 разных значений requested_protocols от одного IP

  Bruteforcer:
    +10 учётные данные захвачены
    +5  сессия дошла до x224_cc: RDP_LEGACY
    +3  downgrade_requested, а затем retry с PROTOCOL_RDP
    +2  ≥5 сессий от одного IP

  Accidental:
    n=1, нет legacy, нет учётных данных, scanner_score=0

Решение: max(scanner_score, brute_score) определяет класс.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

_SCANNER_RE = re.compile(
    r"nmap|masscan|zmap|zgrab|rdpscan|metasploit|shodan|censys|nuclei"
    r"|stretchoid|internetmeasurement|alphasoc|mirai"
    r"|mstshash=test",  # Metasploit auxiliary/scanner/rdp/rdp_scanner default
    re.IGNORECASE,
)


@dataclass
class SessionInfo:
    ip: str
    port: int
    stages: list[str] = field(default_factory=list)
    requested_protocols: int = 0
    cookie: str = ""
    errors: list[str] = field(default_factory=list)
    selected: Optional[str] = None  # RDP_LEGACY | SSL | HYBRID
    has_credentials: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0
    channel_names: list[str] = field(default_factory=list)  # CS_NET virtual channels
    client_build: int = 0                                    # CS_CORE clientBuild


@dataclass
class IpAnalysis:
    ip: str
    classification: str   # scanner / bruteforcer / accidental / unknown
    confidence: str       # high / medium / low
    reasons: list[str]
    sessions_total: int
    protocols_seen: list[str]
    has_credentials: bool
    cve_hints: list[str] = field(default_factory=list)


# ── CVE fingerprints ─────────────────────────────────────────────────────────

# Channel names that legitimate RDP clients NEVER request.
# Their presence in CS_NET is an exploit fingerprint.
_CVE_CHANNEL_SIGS: dict[str, str] = {
    "MS_T120": "CVE-2019-0708:BlueKeep",    # BlueKeep — kernel pool spray via MS_T120
}

# clientBuild values used by known PoC / framework tools (0 = unset, tool forgot to fill)
_EXPLOIT_CLIENT_BUILDS: dict[int, str] = {
    0x00000000: "client_build:0",            # uninitialized — common in PoCs
    0x00000A28: "client_build:Metasploit",   # Metasploit RDP module default (0x0A28)
}


def detect_cve_hints(sessions: list[SessionInfo]) -> list[str]:
    """
    Return list of CVE / anomaly strings detected across all sessions from one IP.
    Called from classify_ip() — results go into IpAnalysis.cve_hints and reasons.
    """
    hits: list[str] = []
    seen: set[str] = set()

    all_channels: set[str] = set()
    for s in sessions:
        all_channels.update(s.channel_names)

    # Channel-name fingerprinting
    for channel, cve_label in _CVE_CHANNEL_SIGS.items():
        if channel in all_channels and cve_label not in seen:
            hits.append(cve_label)
            seen.add(cve_label)

    # Anomalous channel count (legitimate clients use 3–10)
    max_ch = max((len(s.channel_names) for s in sessions if s.channel_names), default=0)
    if max_ch > 30:
        label = f"anomalous_channel_count:{max_ch}"
        if label not in seen:
            hits.append(label)
            seen.add(label)
    elif max_ch > 20:
        label = f"high_channel_count:{max_ch}"
        if label not in seen:
            hits.append(label)
            seen.add(label)

    # PoC / exploit tool fingerprint via clientBuild.
    # Only meaningful if session reached mcs_connect_initial — otherwise
    # client_build=0 is just the uninitialized default (e.g. TLS probes).
    for s in sessions:
        if "mcs_connect_initial" not in s.stages:
            continue
        if s.client_build in _EXPLOIT_CLIENT_BUILDS:
            label = _EXPLOIT_CLIENT_BUILDS[s.client_build]
            if label not in seen:
                hits.append(label)
                seen.add(label)

    return hits


def classify_ip(sessions: list[SessionInfo]) -> IpAnalysis:
    """Classify all known sessions from one IP address."""
    reasons: list[str] = []
    protocols = sorted({s.selected for s in sessions if s.selected})
    has_creds = any(s.has_credentials for s in sessions)
    reached_legacy = any(s.selected == "RDP_LEGACY" for s in sessions)
    n = len(sessions)
    scanner_score = 0
    brute_score = 0

    # ─── CVE fingerprinting ──────────────────────────────────────────
    cve_hints = detect_cve_hints(sessions)
    if cve_hints:
        # Each confirmed CVE fingerprint is a strong scanner signal
        cve_count     = sum(1 for h in cve_hints if h.startswith("CVE-"))
        exploit_count = sum(1 for h in cve_hints if h.startswith("client_build:"))
        scanner_score += 8 * cve_count
        scanner_score += 6 * exploit_count   # PoC/framework tool fingerprint
        reasons.extend(cve_hints)

    # ─── Scanner signals ────────────────────────────────────────────
    for s in sessions:
        if s.cookie and _SCANNER_RE.search(s.cookie):
            scanner_score += 5
            reasons.append(f"scanner_cookie:{s.cookie!r}")
            break

    for s in sessions:
        if any("TPKT" in e for e in s.errors):
            scanner_score += 3
            reasons.append("tls_direct_probe")
            break

    # no_tpkt_silent_drop — TCP connect без данных (port check или медленный TLS-зонд)
    if any("no_tpkt_silent_drop" in s.stages for s in sessions):
        scanner_score += 2
        reasons.append("silent_drop_probe")

    # HYBRID_EX bit (0x08) — автоматизированный современный клиент (Shodan, Censys)
    for s in sessions:
        if s.requested_protocols & 0x08:
            scanner_score += 3
            reasons.append("hybrid_ex_protocol")
            break

    # Множество быстрых соединений
    ts_list = sorted(s.first_ts for s in sessions if s.first_ts > 0)
    if len(ts_list) >= 3 and (ts_list[-1] - ts_list[0]) < 120:
        scanner_score += 2
        reasons.append(
            f"rapid_multiconn:{len(ts_list)}x_in_{ts_list[-1] - ts_list[0]:.0f}s"
        )

    # Разные значения requested_protocols
    if len({s.requested_protocols for s in sessions}) > 2:
        scanner_score += 1
        reasons.append("multi_proto_variants")

    # ─── Bruteforcer signals ─────────────────────────────────────────
    if has_creds:
        brute_score += 10
        reasons.append("credentials_captured")

    if reached_legacy:
        brute_score += 5
        reasons.append("reached_rdp_legacy")

    had_downgrade = any("downgrade_requested" in s.stages for s in sessions)
    if had_downgrade and reached_legacy:
        brute_score += 3
        reasons.append("downgrade_then_legacy_retry")

    if n >= 5:
        brute_score += 2
        reasons.append(f"high_session_count:{n}")

    # ─── Decision ────────────────────────────────────────────────────
    if scanner_score >= max(brute_score, 3):
        cls, conf = "scanner", "high" if scanner_score >= 5 else "medium"
    elif brute_score >= 5:
        cls, conf = "bruteforcer", "high" if has_creds else "medium"
    elif n == 1 and not reached_legacy and not has_creds and scanner_score == 0:
        cls, conf = "accidental", "medium"
    else:
        cls, conf = "unknown", "low"
        if not reasons:
            reasons.append("insufficient_data")

    return IpAnalysis(
        ip=sessions[0].ip,
        classification=cls,
        confidence=conf,
        reasons=reasons,
        sessions_total=n,
        protocols_seen=protocols,
        has_credentials=has_creds,
        cve_hints=cve_hints,
    )


# ── Threat scoring (scope) ────────────────────────────────────────────────────

#: Базовый балл по типу угрозы (до применения множителя confidence)
_CLS_BASE: dict[str, int] = {
    "bruteforcer": 50,
    "scanner":     35,   # было 30; подняли чтобы scanner/high day1 = 35
    "accidental":   0,
    "unknown":      5,
}

#: Множитель уверенности
_CONF_MULT: dict[str, float] = {
    "high":   1.0,
    "medium": 0.7,
    "low":    0.4,
}


def compute_scope(
    classification: str,
    confidence: str,
    threat_days_count: int,
) -> int:
    """
    Рейтинг угрозы IP: 0–100.

      base       = _CLS_BASE[cls] * _CONF_MULT[conf]   (0–50)
      days_bonus = min(threat_days * 5, 50)             (0–50)

    scope >= 70  →  блокировка 60 дней
    scope >= 50  →  блокировка 30 дней
    scope >= 25  →  блокировка  7 дней
    scope <  25  →  без блокировки
    """
    base       = _CLS_BASE.get(classification, 5) * _CONF_MULT.get(confidence, 0.5)
    days_bonus = min(threat_days_count * 5, 50)
    return min(100, int(base + days_bonus))


def compute_block_until(scope: int, last_seen_ts: float) -> Optional[str]:
    """
    Дата окончания блокировки по рейтингу угрозы.
    Возвращает ISO-8601 строку или None (блокировка не нужна).
    """
    if scope >= 70:
        days = 60
    elif scope >= 50:
        days = 30
    elif scope >= 25:
        days = 7
    else:
        return None
    dt = datetime.fromtimestamp(last_seen_ts, tz=timezone.utc) + timedelta(days=days)
    return dt.isoformat()


# ── Subnet correlation ────────────────────────────────────────────────────────

def _has_tpkt_probe(sessions: list[SessionInfo]) -> bool:
    """True if any session looks like a TLS/port probe, not a real RDP client."""
    return any(
        any("TPKT" in e for e in s.errors) or "no_tpkt_silent_drop" in s.stages
        for s in sessions
    )


def _probe_timestamps(sessions: list[SessionInfo]) -> list[float]:
    """Return first_ts for sessions that are TPKT probes."""
    return [
        s.first_ts
        for s in sessions
        if s.first_ts > 0
        and (any("TPKT" in e for e in s.errors) or "no_tpkt_silent_drop" in s.stages)
    ]


def correlate_subnet_scan(
    by_ip: dict[str, list[SessionInfo]],
    window_secs: float = 3600.0,
    min_ips: int = 3,
) -> set[str]:
    """
    Detect coordinated /24 subnet scans.

    Returns the set of IPs participating in a /24 subnet where ≥ min_ips
    distinct addresses sent TPKT-probe traffic within window_secs seconds.
    IPv6: /48 is used instead of /24.
    """
    import ipaddress

    # /24-network string → [(ip, earliest_probe_ts)]
    subnet_map: dict[str, list[tuple[str, float]]] = {}
    for ip, sessions in by_ip.items():
        if not _has_tpkt_probe(sessions):
            continue
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(
                f"{addr}/24" if addr.version == 4 else f"{addr}/48",
                strict=False,
            )
        except ValueError:
            continue
        ts_list = _probe_timestamps(sessions)
        if not ts_list:
            continue
        subnet_map.setdefault(str(net), []).append((ip, min(ts_list)))

    coordinated: set[str] = set()
    for entries in subnet_map.values():
        if len(entries) < min_ips:
            continue
        ts_sorted = sorted(t for _, t in entries)
        if ts_sorted[-1] - ts_sorted[0] <= window_secs:
            for ip, _ in entries:
                coordinated.add(ip)

    return coordinated
