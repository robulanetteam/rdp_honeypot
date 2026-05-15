"""
Минимальная реализация частей RDP протокола, нужных для маскировки
honeypot под настоящий Windows Server.

Реализованы:
  * TPKT (RFC 1006) — упаковка TCP-данных
  * X.224 (ITU-T X.224 Class 0) — Connection Request / Confirm
  * RDP_NEG_REQ / RDP_NEG_RSP — выбор protocol (SSL/HYBRID/HYBRID_EX)
  * MCS Connect Initial / Connect Response (упрощённо)
  * Client Info PDU parse (Standard RDP Security legacy)

Ссылки:
  * [MS-RDPBCGR] — Remote Desktop Protocol: Basic Connectivity and Graphics Remoting
  * RFC 905 / 1006

Этот модуль НЕ полная реализация — только то, что отдаёт настоящий
Windows Server 2008 R2 / 2012 при сканировании и при первичном handshake.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# ---------------- RDP Negotiation flags (MS-RDPBCGR 2.2.1.1.1) ----------------

PROTOCOL_RDP = 0x00000000
PROTOCOL_SSL = 0x00000001
PROTOCOL_HYBRID = 0x00000002   # CredSSP (NLA)
PROTOCOL_RDSTLS = 0x00000004
PROTOCOL_HYBRID_EX = 0x00000008

RDP_NEG_REQ = 0x01
RDP_NEG_RSP = 0x02
RDP_NEG_FAILURE = 0x03

# X.224 PDU codes
X224_TPDU_CONNECTION_REQUEST = 0xE0
X224_TPDU_CONNECTION_CONFIRM = 0xD0
X224_TPDU_DATA = 0xF0


# ---------------- TPKT ----------------

def tpkt_pack(payload: bytes) -> bytes:
    """TPKT header: version=3, reserved=0, length (incl header)."""
    length = len(payload) + 4
    return struct.pack(">BBH", 3, 0, length) + payload


def tpkt_unpack(data: bytes) -> tuple[bytes, bytes]:
    """Возвращает (payload, остаток-байтов). Бросает ValueError если данных мало."""
    if len(data) < 4:
        raise ValueError("TPKT: недостаточно данных для заголовка")
    version, _reserved, length = struct.unpack(">BBH", data[:4])
    if version != 3:
        raise ValueError(f"TPKT: неожиданная версия {version}")
    if length < 4 or length > 0xFFFF:
        raise ValueError(f"TPKT: некорректная длина {length}")
    if len(data) < length:
        raise ValueError("TPKT: пакет не полностью получен")
    return data[4:length], data[length:]


# ---------------- X.224 Connection Request parser ----------------

@dataclass
class X224ConnectionRequest:
    cookie: str | None        # "mstshash=..." cookie
    requested_protocols: int  # bitmask из PROTOCOL_*
    raw: bytes

def parse_x224_cr(tpdu: bytes) -> X224ConnectionRequest:
    """
    Парсит X.224 Connection Request с опциональным RDP_NEG_REQ.
    Формат:
        1   LI (length indicator)
        1   TPDU code (0xE0 = CR)
        2   DST-REF (0x0000)
        2   SRC-REF
        1   class option (0x00)
        ?   userData: cookie/mstshash + RDP_NEG_REQ (8 bytes)
    """
    if len(tpdu) < 7:
        raise ValueError("X.224 CR: слишком короткий PDU")
    li = tpdu[0]
    code = tpdu[1]
    if code != X224_TPDU_CONNECTION_REQUEST:
        raise ValueError(f"X.224: ожидался CR (0xE0), получен {code:#x}")

    # Variable part после фиксированных 7 байт может содержать:
    #   - "Cookie: mstshash=...\r\n"
    #   - RDP_NEG_REQ (8 байт)
    user_data = tpdu[7 : 1 + li] if li + 1 <= len(tpdu) else b""

    cookie = None
    requested = PROTOCOL_RDP
    # Поиск cookie до \r\n
    if user_data.startswith(b"Cookie:"):
        end = user_data.find(b"\r\n")
        if end != -1:
            try:
                cookie = user_data[:end].decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                cookie = repr(user_data[:end])
            user_data = user_data[end + 2:]

    # RDP_NEG_REQ
    if len(user_data) >= 8 and user_data[0] == RDP_NEG_REQ:
        # type(1), flags(1), length(2)=8, requestedProtocols(4)
        _t, _flags, length, requested = struct.unpack("<BBHI", user_data[:8])
        if length != 8:
            requested = PROTOCOL_RDP

    return X224ConnectionRequest(cookie=cookie, requested_protocols=requested, raw=tpdu)


# ---------------- X.224 Connection Confirm builder ----------------

def build_x224_cc(selected_protocol: int) -> bytes:
    """
    Connection Confirm + RDP_NEG_RSP.
    Размер фиксированный: 7 (X.224) + 8 (NEG_RSP) = 15 байт.
    """
    neg_rsp = struct.pack(
        "<BBHI",
        RDP_NEG_RSP,
        0x01,            # flags: EXTENDED_CLIENT_DATA_SUPPORTED (Windows Vista/7/2008 R2+)
        8,               # length
        selected_protocol,
    )
    # X.224 CC: LI, code, DST-REF, SRC-REF, class
    li = 6 + len(neg_rsp)  # 6 после самого LI байта, + neg_rsp
    x224 = struct.pack(
        ">BBHHB",
        li,
        X224_TPDU_CONNECTION_CONFIRM,
        0x0000,          # DST-REF
        0x1234,          # SRC-REF (произвольный)
        0x00,            # class option
    ) + neg_rsp
    return tpkt_pack(x224)


def build_x224_neg_failure(failure_code: int = 0x00000002) -> bytes:
    """
    Возвращает CC PDU с RDP_NEG_FAILURE.
    Коды (MS-RDPBCGR 2.2.1.2.2):
      0x00000001 SSL_REQUIRED_BY_SERVER
      0x00000002 SSL_NOT_ALLOWED_BY_SERVER
      0x00000003 SSL_CERT_NOT_ON_SERVER
      0x00000004 INCONSISTENT_FLAGS
      0x00000005 HYBRID_REQUIRED_BY_SERVER
      0x00000006 SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER
    """
    failure = struct.pack(
        "<BBHI",
        RDP_NEG_FAILURE,
        0x00,
        8,
        failure_code,
    )
    li = 6 + len(failure)
    x224 = struct.pack(
        ">BBHHB",
        li,
        X224_TPDU_CONNECTION_CONFIRM,
        0x0000,
        0x1234,
        0x00,
    ) + failure
    return tpkt_pack(x224)


# ---------------- MCS Connect Initial parse (грубо, только GCC user data) ----------------

def find_client_core_data(mcs_payload: bytes) -> dict | None:
    """
    Очень упрощённый парсер MCS Connect Initial → GCC user data → CS_CORE (0xC001).
    Достаёт некоторые поля clientCoreData: version, desktopWidth/Height,
    clientName, build, productId, clientDigProductId.

    Не используется в hot-path — нужен только для логирования отпечатков клиента.
    """
    # Ищем сигнатуру CS_CORE (0xC001) в payload
    idx = mcs_payload.find(b"\x01\xc0")
    if idx < 0 or idx + 4 > len(mcs_payload):
        return None
    try:
        header_type, header_len = struct.unpack("<HH", mcs_payload[idx : idx + 4])
        block = mcs_payload[idx + 4 : idx + header_len]
        if len(block) < 32:
            return None
        version = struct.unpack("<I", block[0:4])[0]
        desktop_w, desktop_h = struct.unpack("<HH", block[4:8])
        # colorDepth (2), SASSequence (2), keyboardLayout (4), clientBuild (4)
        client_build = struct.unpack("<I", block[16:20])[0]
        # clientName: 32 байта UTF-16LE, null-terminated
        client_name = block[20:52].decode("utf-16-le", errors="replace").rstrip("\x00")
        return {
            "rdp_version": f"0x{version:08x}",
            "desktop": f"{desktop_w}x{desktop_h}",
            "client_build": client_build,
            "client_name": client_name,
        }
    except Exception:
        return None
