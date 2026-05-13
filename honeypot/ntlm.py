"""
Минимальная реализация NTLMSSP server-side для honeypot.

Реализованы:
  * парсинг NEGOTIATE_MESSAGE (type 1)
  * генерация CHALLENGE_MESSAGE (type 2) с правильной TargetInfo
  * парсинг AUTHENTICATE_MESSAGE (type 3) с извлечением:
      - DomainName
      - UserName
      - Workstation
      - LM/NT response (NTLMv1 или NTLMv2 hash)

Используем NTLMSSP-протокол по [MS-NLMP].

Структура NTLMSSP сообщений достаточно жёсткая — поэтому большинство сканеров
не сможет отличить нашу реализацию от настоящей Windows-машины.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass

NTLMSSP_SIGNATURE = b"NTLMSSP\x00"

# Message types
NTLM_NEGOTIATE = 0x00000001
NTLM_CHALLENGE = 0x00000002
NTLM_AUTHENTICATE = 0x00000003

# Negotiate flags (часто отправляемые сочетания, как у Windows Server)
FLAGS_SERVER_CHALLENGE = (
    0x00000001  # UNICODE
    | 0x00000004  # REQUEST_TARGET
    | 0x00000200  # NTLM
    | 0x00010000  # NTLM2_KEY
    | 0x00080000  # ALWAYS_SIGN
    | 0x00800000  # VERSION
    | 0x20000000  # KEY_EXCHANGE
    | 0x40000000  # 128
    | 0x80000000  # 56
    | 0x00100000  # TARGET_TYPE_DOMAIN
)

# AV_PAIR ids (TargetInfo)
MSV_AV_EOL = 0x0000
MSV_AV_NB_COMPUTER_NAME = 0x0001
MSV_AV_NB_DOMAIN_NAME = 0x0002
MSV_AV_DNS_COMPUTER_NAME = 0x0003
MSV_AV_DNS_DOMAIN_NAME = 0x0004
MSV_AV_TIMESTAMP = 0x0007


def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


def _filetime_now() -> bytes:
    """Windows FILETIME (100ns since 1601-01-01) для AV_TIMESTAMP."""
    epoch_diff = 116444736000000000  # 100ns между 1601 и 1970
    now_100ns = int(time.time() * 10_000_000) + epoch_diff
    return struct.pack("<Q", now_100ns)


def _av_pair(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def build_target_info(
    netbios_computer: str,
    netbios_domain: str,
    dns_computer: str,
    dns_domain: str,
) -> bytes:
    parts = [
        _av_pair(MSV_AV_NB_DOMAIN_NAME, _utf16le(netbios_domain)),
        _av_pair(MSV_AV_NB_COMPUTER_NAME, _utf16le(netbios_computer)),
        _av_pair(MSV_AV_DNS_DOMAIN_NAME, _utf16le(dns_domain)),
        _av_pair(MSV_AV_DNS_COMPUTER_NAME, _utf16le(dns_computer)),
        _av_pair(MSV_AV_TIMESTAMP, _filetime_now()),
        _av_pair(MSV_AV_EOL, b""),
    ]
    return b"".join(parts)


def build_challenge_message(
    target_name: str,
    netbios_computer: str,
    netbios_domain: str,
    dns_computer: str,
    dns_domain: str,
    server_challenge: bytes,
) -> bytes:
    """
    NTLMSSP CHALLENGE_MESSAGE [MS-NLMP 2.2.1.2].
    """
    if len(server_challenge) != 8:
        raise ValueError("server_challenge должен быть 8 байт")

    target_name_b = _utf16le(target_name)
    target_info_b = build_target_info(
        netbios_computer, netbios_domain, dns_computer, dns_domain
    )

    # Layout:
    #   Signature (8)
    #   MessageType (4) = 2
    #   TargetNameFields (8): len, max, offset
    #   NegotiateFlags (4)
    #   ServerChallenge (8)
    #   Reserved (8)
    #   TargetInfoFields (8)
    #   Version (8)
    #   ... payload (target_name, target_info)
    fixed_size = 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8  # 56
    target_name_offset = fixed_size
    target_info_offset = target_name_offset + len(target_name_b)

    # Windows Server 2008 R2 version: MajorVersion=6, MinorVersion=1, Build=7601, NTLMRevision=15
    version = struct.pack("<BBHBBBB", 6, 1, 7601, 0, 0, 0, 15)

    header = (
        NTLMSSP_SIGNATURE
        + struct.pack("<I", NTLM_CHALLENGE)
        + struct.pack(
            "<HHI", len(target_name_b), len(target_name_b), target_name_offset
        )
        + struct.pack("<I", FLAGS_SERVER_CHALLENGE)
        + server_challenge
        + b"\x00" * 8
        + struct.pack(
            "<HHI", len(target_info_b), len(target_info_b), target_info_offset
        )
        + version
    )
    return header + target_name_b + target_info_b


# ----------------- parsing -----------------

@dataclass
class NtlmNegotiate:
    flags: int
    domain: str | None
    workstation: str | None


@dataclass
class NtlmAuthenticate:
    domain: str
    user: str
    workstation: str
    lm_response: bytes
    nt_response: bytes
    flags: int

    def is_ntlmv2(self) -> bool:
        # NTLMv2 response > 24 байт (NTLMv1 response = 24, NTLMv2 = 16 + AVPairs)
        return len(self.nt_response) > 24


def _read_string_field(data: bytes, base: int) -> str:
    """Читает SecurityBuffer (Len, MaxLen, Offset) → строка UTF-16LE."""
    if len(data) < base + 8:
        return ""
    length, _maxlen, offset = struct.unpack("<HHI", data[base : base + 8])
    chunk = data[offset : offset + length]
    try:
        return chunk.decode("utf-16-le", errors="replace")
    except Exception:
        return ""


def _read_bytes_field(data: bytes, base: int) -> bytes:
    if len(data) < base + 8:
        return b""
    length, _maxlen, offset = struct.unpack("<HHI", data[base : base + 8])
    return data[offset : offset + length]


def parse_ntlm_message(data: bytes) -> tuple[int, NtlmNegotiate | NtlmAuthenticate | None]:
    """Определяет тип сообщения и парсит. Возвращает (msg_type, obj-or-None)."""
    if len(data) < 12 or not data.startswith(NTLMSSP_SIGNATURE):
        return 0, None
    msg_type = struct.unpack("<I", data[8:12])[0]

    if msg_type == NTLM_NEGOTIATE:
        if len(data) < 32:
            return msg_type, None
        flags = struct.unpack("<I", data[12:16])[0]
        domain = _read_string_field(data, 16)
        workstation = _read_string_field(data, 24)
        return msg_type, NtlmNegotiate(flags=flags, domain=domain or None,
                                       workstation=workstation or None)

    if msg_type == NTLM_AUTHENTICATE:
        if len(data) < 64:
            return msg_type, None
        # Layout (offsets):
        #  12  LmChallengeResponseFields (8)
        #  20  NtChallengeResponseFields (8)
        #  28  DomainNameFields (8)
        #  36  UserNameFields (8)
        #  44  WorkstationFields (8)
        #  52  EncryptedRandomSessionKeyFields (8)
        #  60  NegotiateFlags (4)
        lm = _read_bytes_field(data, 12)
        nt = _read_bytes_field(data, 20)
        domain = _read_string_field(data, 28)
        user = _read_string_field(data, 36)
        workstation = _read_string_field(data, 44)
        flags = struct.unpack("<I", data[60:64])[0]
        return msg_type, NtlmAuthenticate(
            domain=domain, user=user, workstation=workstation,
            lm_response=lm, nt_response=nt, flags=flags,
        )

    return msg_type, None


def random_challenge() -> bytes:
    return os.urandom(8)


def format_ntlm_hash_for_hashcat(
    auth: NtlmAuthenticate, server_challenge: bytes
) -> str:
    """
    Возвращает строку в формате hashcat:
      NetNTLMv2: user::domain:server_challenge:HMAC:blob
      NetNTLMv1: user::domain:LM_resp:NT_resp:server_challenge
    Полезно для офлайн-brute и для логирования.
    """
    if auth.is_ntlmv2():
        # NTLMv2 nt_response = HMAC(16) + NTLMv2_CLIENT_CHALLENGE blob
        hmac_part = auth.nt_response[:16].hex()
        blob = auth.nt_response[16:].hex()
        return f"{auth.user}::{auth.domain}:{server_challenge.hex()}:{hmac_part}:{blob}"
    else:
        return (
            f"{auth.user}::{auth.domain}:"
            f"{auth.lm_response.hex()}:{auth.nt_response.hex()}:"
            f"{server_challenge.hex()}"
        )
