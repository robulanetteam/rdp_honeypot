"""
RDP Honeypot — гибридный stealth listener.

Стратегия:
  1.  Если клиент запросил PROTOCOL_HYBRID (NLA) — отвечаем
      NEG_FAILURE = SSL_NOT_ALLOWED_BY_SERVER. Реальный mstsc после
      этого закрывается, но **сканеры и боты (hydra/ncrack/medusa)**
      обычно retry'ят с PROTOCOL_RDP → попадают в legacy-ветку.
  2.  Если клиент сразу запросил PROTOCOL_RDP — идём в legacy-ветку
      (MCS + RC4 + RSA), ловим **plaintext password** из Client Info PDU.
  3.  Если клиент запросил PROTOCOL_SSL без HYBRID — соглашаемся,
      поднимаем TLS, после TLS клиент шлёт Client Info **в открытом виде**
      внутри TLS-канала — тоже plaintext password.
  4.  В довесок: если клиент после downgrade на PROTOCOL_HYBRID
      настойчив (CredSSP по TLS) — мы примем TLS, поговорим NTLMSSP и
      хотя бы захватим NetNTLMv2 hash.

Все события и captured-пароли пишутся в JSONL под /var/log/honeypot/.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import os
import socket
import ssl
import struct
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import ntlm
import rdp_protocol as rdp
import rdp_legacy as legacy

# --------------- config ---------------

HOST = os.environ.get("HONEYPOT_HOST", "0.0.0.0")
PORT = int(os.environ.get("HONEYPOT_PORT", "3389"))

NETBIOS_COMPUTER = os.environ.get("HONEYPOT_COMPUTER", "WIN-SRV2008")
NETBIOS_DOMAIN = os.environ.get("HONEYPOT_DOMAIN", "CORP")
DNS_COMPUTER = os.environ.get("HONEYPOT_DNS_COMPUTER", "WIN-SRV2008.corp.local")
DNS_DOMAIN = os.environ.get("HONEYPOT_DNS_DOMAIN", "corp.local")

# Если true — будем форсить downgrade с NLA на legacy (для ловли plaintext).
# Если false — отвечаем PROTOCOL_HYBRID и ловим только NTLM hash.
FORCE_LEGACY_DOWNGRADE = os.environ.get("HONEYPOT_FORCE_LEGACY", "1") == "1"

LOG_DIR = Path(os.environ.get("HONEYPOT_LOG_DIR", "/var/log/honeypot"))
CONN_LOG = LOG_DIR / "connections.jsonl"
CRED_LOG = LOG_DIR / "credentials.jsonl"

CERT_DIR = Path(os.environ.get("HONEYPOT_CERT_DIR", "/var/log/honeypot"))
CERT_FILE = CERT_DIR / "server.crt"
KEY_FILE = CERT_DIR / "server.key"

READ_TIMEOUT = 8.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("honeypot")


# --------------- TLS-сертификат "под Windows" ---------------

def _ensure_certificate() -> None:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    log.info("Генерация TLS-сертификата для %s", DNS_COMPUTER)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, NETBIOS_COMPUTER),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=7))
        .not_valid_after(now + dt.timedelta(days=365 * 10))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(NETBIOS_COMPUTER),
                x509.DNSName(DNS_COMPUTER),
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_FILE.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(KEY_FILE, 0o600)


def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
            "AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA"
        )
    except ssl.SSLError:
        pass
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    return ctx


# --------------- серверный RSA-keypair для legacy ветки ---------------

class LegacyServerKey:
    """2048-bit RSA keypair, генерируется один раз при старте процесса."""

    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048,
        )
        pub = self.private_key.public_key().public_numbers()
        priv = self.private_key.private_numbers()
        self.modulus_int = pub.n
        self.public_exp = pub.e
        self.private_exp_int = priv.d
        self.modulus_byte_len = (self.modulus_int.bit_length() + 7) // 8  # 256
        self.modulus_le = self.modulus_int.to_bytes(
            self.modulus_byte_len, "little"
        )

LEGACY_KEY: LegacyServerKey | None = None


# --------------- логирование ---------------

def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _append_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")


def log_connection(peer, stage, extra=None):
    obj = {
        "timestamp": _now_iso(),
        "logger": "mitm.connections",
        "source_ip": peer[0],
        "source_port": peer[1],
        "stage": stage,
    }
    if extra:
        obj.update(extra)
    _append_json(CONN_LOG, obj)
    log.info("[%s:%d] %s %s", peer[0], peer[1], stage, extra or "")


def log_credentials(peer, creds):
    obj = {
        "timestamp": _now_iso(),
        "logger": "credentials",
        "source_ip": peer[0],
        "source_port": peer[1],
    }
    obj.update(creds)
    _append_json(CRED_LOG, obj)
    log.info(
        "[%s:%d] CREDENTIALS via=%s user=%s domain=%s pwd=%s",
        peer[0], peer[1],
        creds.get("captured_via"),
        creds.get("username"),
        creds.get("domain"),
        "<PLAINTEXT>" if creds.get("password") else "<hash only>",
    )


# --------------- TPKT reader ---------------

async def read_tpkt(reader, timeout=READ_TIMEOUT):
    header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    version, _r, length = struct.unpack(">BBH", header)
    if version != 3 or length < 4:
        raise ValueError(f"невалидный TPKT: v={version} len={length}")
    body = await asyncio.wait_for(reader.readexactly(length - 4), timeout=timeout)
    return body


# --------------- main connection handler ---------------

async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    log_connection(peer, "tcp_accept")

    try:
        # ---- Шаг 1: X.224 CR ----
        try:
            cr_payload = await read_tpkt(reader)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            log_connection(peer, "no_tpkt_silent_drop")
            return

        try:
            cr = rdp.parse_x224_cr(cr_payload)
        except ValueError as e:
            log_connection(peer, "x224_parse_fail", {"error": str(e)})
            return

        log_connection(peer, "x224_cr", {
            "cookie": cr.cookie,
            "requested_protocols": f"0x{cr.requested_protocols:08x}",
        })

        # ---- Шаг 2: выбор протокола по гибридной стратегии ----
        # Приоритеты (для максимума ловли plaintext):
        #   * клиент запросил только legacy (PROTOCOL_RDP) → legacy ветка
        #   * клиент запросил PROTOCOL_SSL без HYBRID → SSL ветка (plaintext в TLS)
        #   * клиент запросил HYBRID и FORCE_LEGACY_DOWNGRADE=1 → NEG_FAILURE
        #     SSL_NOT_ALLOWED_BY_SERVER → клиент может retry'нуть legacy
        #   * иначе соглашаемся на HYBRID и ловим NetNTLM hash
        if cr.requested_protocols == rdp.PROTOCOL_RDP:
            await _handle_legacy(reader, writer, peer, cr)
            return

        if (cr.requested_protocols & rdp.PROTOCOL_SSL) and not (
            cr.requested_protocols & rdp.PROTOCOL_HYBRID
        ):
            await _handle_ssl_no_nla(reader, writer, peer, cr)
            return

        if cr.requested_protocols & rdp.PROTOCOL_HYBRID:
            if FORCE_LEGACY_DOWNGRADE:
                # SSL_NOT_ALLOWED_BY_SERVER (0x2) — провоцирует retry без NLA
                writer.write(rdp.build_x224_neg_failure(0x00000002))
                await writer.drain()
                log_connection(peer, "downgrade_requested", {
                    "code": "SSL_NOT_ALLOWED_BY_SERVER",
                })
                return
            await _handle_hybrid_nla(reader, writer, peer, cr)
            return

        # По умолчанию — отказ
        writer.write(rdp.build_x224_neg_failure(0x00000001))
        await writer.drain()
        log_connection(peer, "unsupported_protocols", {
            "requested": f"0x{cr.requested_protocols:08x}",
        })

    except (ConnectionResetError, BrokenPipeError):
        log_connection(peer, "connection_reset")
    except Exception as e:
        log_connection(peer, "exception", {"error": repr(e)})
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ====================================================================
#                          NLA (HYBRID) ветка
# ====================================================================

async def _handle_hybrid_nla(reader, writer, peer, cr):
    writer.write(rdp.build_x224_cc(rdp.PROTOCOL_HYBRID))
    await writer.drain()
    log_connection(peer, "x224_cc", {"selected": "HYBRID"})

    try:
        await writer.start_tls(_build_ssl_context(), server_side=True)
    except (ssl.SSLError, OSError) as e:
        log_connection(peer, "tls_handshake_fail", {"error": str(e)})
        return
    log_connection(peer, "tls_established", {
        "cipher": writer.get_extra_info("cipher"),
    })

    await _credssp_loop(reader, writer, peer)


async def _credssp_loop(reader, writer, peer):
    # Шаг A: TSRequest c NTLMSSP NEGOTIATE
    try:
        chunk = await asyncio.wait_for(reader.read(8192), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        log_connection(peer, "credssp_neg_timeout")
        return
    if not chunk:
        return
    nego_blob = _extract_ntlm_blob(chunk)
    if not nego_blob:
        log_connection(peer, "credssp_no_ntlm_in_neg")
        return
    msg_type, neg = ntlm.parse_ntlm_message(nego_blob)
    if msg_type != ntlm.NTLM_NEGOTIATE:
        return
    log_connection(peer, "ntlm_negotiate",
                   {"flags": f"0x{neg.flags:08x}" if neg else None})

    # Шаг B: CHALLENGE
    server_challenge = ntlm.random_challenge()
    challenge = ntlm.build_challenge_message(
        target_name=NETBIOS_DOMAIN,
        netbios_computer=NETBIOS_COMPUTER,
        netbios_domain=NETBIOS_DOMAIN,
        dns_computer=DNS_COMPUTER,
        dns_domain=DNS_DOMAIN,
        server_challenge=server_challenge,
    )
    writer.write(_wrap_tsrequest_with_ntlm(challenge))
    await writer.drain()

    # Шаг C: AUTHENTICATE
    try:
        chunk = await asyncio.wait_for(reader.read(16384), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        return
    auth_blob = _extract_ntlm_blob(chunk)
    if not auth_blob:
        return
    msg_type, auth = ntlm.parse_ntlm_message(auth_blob)
    if msg_type != ntlm.NTLM_AUTHENTICATE or auth is None:
        return

    hashcat = ntlm.format_ntlm_hash_for_hashcat(auth, server_challenge)
    log_credentials(peer, {
        "captured_via": "nla_ntlmssp",
        "username": auth.user,
        "domain": auth.domain,
        "workstation": auth.workstation,
        "password": None,
        "ntlm_version": "v2" if auth.is_ntlmv2() else "v1",
        "server_challenge": server_challenge.hex(),
        "hashcat": hashcat,
    })

    writer.write(_build_credssp_error())
    await writer.drain()


def _extract_ntlm_blob(data):
    idx = data.find(ntlm.NTLMSSP_SIGNATURE)
    return data[idx:] if idx >= 0 else None


# ====================================================================
#                        SSL без NLA (plaintext in TLS)
# ====================================================================

async def _handle_ssl_no_nla(reader, writer, peer, cr):
    writer.write(rdp.build_x224_cc(rdp.PROTOCOL_SSL))
    await writer.drain()
    log_connection(peer, "x224_cc", {"selected": "SSL"})
    try:
        await writer.start_tls(_build_ssl_context(), server_side=True)
    except (ssl.SSLError, OSError) as e:
        log_connection(peer, "tls_handshake_fail", {"error": str(e)})
        return
    log_connection(peer, "tls_established", {
        "cipher": writer.get_extra_info("cipher"),
    })
    # В этой ветке клиент шлёт MCS Connect Initial / Erect Domain / ...
    # / Client Info PDU **в открытом виде** внутри TLS.
    # Запускаем legacy state-machine, но БЕЗ RSA/RC4: ключи нулевые.
    await _legacy_state_machine(reader, writer, peer, encrypted=False, source="ssl_no_nla")


# ====================================================================
#                          legacy (PROTOCOL_RDP) ветка
# ====================================================================

async def _handle_legacy(reader, writer, peer, cr):
    # Если клиент послал RDP_NEG_REQ — отвечаем NEG_RSP с PROTOCOL_RDP.
    # Если просто X.224 CR без RDP_NEG — отвечаем "голым" CC (без NEG_RSP).
    writer.write(rdp.build_x224_cc(rdp.PROTOCOL_RDP))
    await writer.drain()
    log_connection(peer, "x224_cc", {"selected": "RDP_LEGACY"})
    await _legacy_state_machine(reader, writer, peer, encrypted=True, source="legacy_rdp")


async def _legacy_state_machine(reader, writer, peer, encrypted: bool, source: str):
    """
    Универсальный legacy/SSL flow:
      * читаем MCS Connect Initial
      * шлём MCS Connect Response (с RSA pubkey)
      * читаем Erect Domain Request (молчим)
      * читаем Attach User Request → шлём Attach User Confirm
      * читаем 1-3 Channel Join Requests → шлём Channel Join Confirm
      * (если encrypted=True) читаем Security Exchange → decrypt client_random → derive keys
      * читаем Client Info PDU → decrypt (если encrypted) → parse → credentials
    """
    # ---- MCS Connect Initial ----
    try:
        ci_payload = await read_tpkt(reader)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return
    # MCS Connect Initial = X.224 Data PDU (0xF0 0x80) + BER
    if len(ci_payload) < 3 or ci_payload[0] != 0x02 or ci_payload[1] != 0xF0:
        log_connection(peer, "mcs_unexpected_tpdu", {"first": ci_payload[:4].hex()})
        return
    mcs_initial = ci_payload[3:]  # после X.224 data header (3 байта)

    core = legacy.find_gcc_user_data_block(mcs_initial, 0xC001)
    sec = legacy.find_gcc_user_data_block(mcs_initial, 0xC002)
    net = legacy.find_gcc_user_data_block(mcs_initial, 0xC003)
    requested_channels = 0
    if net and len(net) >= 8:
        requested_channels = struct.unpack("<I", net[4:8])[0]
    log_connection(peer, "mcs_connect_initial", {
        "has_core": bool(core),
        "has_security": bool(sec),
        "channels_requested": requested_channels,
    })

    # ---- MCS Connect Response ----
    server_random = os.urandom(32)
    if LEGACY_KEY is None:
        log.error("LEGACY_KEY не инициализирован")
        return
    try:
        mcs_response = legacy.build_mcs_connect_response(
            server_random=server_random,
            modulus_le=LEGACY_KEY.modulus_le,
            public_exp=LEGACY_KEY.public_exp,
            requested_channels_count=requested_channels,
        )
    except Exception as e:
        log_connection(peer, "mcs_response_build_fail", {"error": repr(e)})
        return
    # Заворачиваем в X.224 Data PDU + TPKT
    x224_data = b"\x02\xf0\x80" + mcs_response
    writer.write(struct.pack(">BBH", 3, 0, len(x224_data) + 4) + x224_data)
    await writer.drain()
    log_connection(peer, "mcs_connect_response_sent")

    # ---- Erect Domain Request (одностороннее) ----
    try:
        await asyncio.wait_for(read_tpkt(reader), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        log_connection(peer, "erect_domain_timeout")
        return

    # ---- Attach User Request → Confirm ----
    try:
        await asyncio.wait_for(read_tpkt(reader), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        return
    auc = legacy.build_attach_user_confirm(1001)
    x224_data = b"\x02\xf0\x80" + auc
    writer.write(struct.pack(">BBH", 3, 0, len(x224_data) + 4) + x224_data)
    await writer.drain()

    # ---- Channel Join Requests (несколько) ----
    for _ in range(max(1, requested_channels + 2)):
        try:
            cj = await asyncio.wait_for(read_tpkt(reader), timeout=2.0)
        except asyncio.TimeoutError:
            break
        # parse channel id из X.224 Data
        if len(cj) < 8:
            continue
        mcs = cj[3:]
        user_id, channel_id = legacy.parse_channel_join_request(mcs)
        cjc = legacy.build_channel_join_confirm(user_id, channel_id)
        x224_data = b"\x02\xf0\x80" + cjc
        writer.write(struct.pack(">BBH", 3, 0, len(x224_data) + 4) + x224_data)
        await writer.drain()

    # ---- Security Exchange (только в legacy encrypted) ----
    client_decrypt_key = None
    if encrypted:
        try:
            sec_exch = await asyncio.wait_for(read_tpkt(reader), timeout=READ_TIMEOUT)
        except asyncio.TimeoutError:
            log_connection(peer, "sec_exchange_timeout")
            return
        if len(sec_exch) < 8:
            return
        mcs_payload = legacy.parse_send_data_request(sec_exch[3:])
        if not mcs_payload:
            log_connection(peer, "no_send_data_request")
            return
        enc_client_random = legacy.parse_security_exchange(mcs_payload)
        if not enc_client_random:
            log_connection(peer, "no_security_exchange")
            return
        try:
            client_random = legacy.decrypt_client_random(
                enc_client_random,
                LEGACY_KEY.private_exp_int,
                LEGACY_KEY.modulus_int,
                LEGACY_KEY.modulus_byte_len,
            )
        except Exception as e:
            log_connection(peer, "client_random_decrypt_fail", {"error": repr(e)})
            return
        keys = legacy.derive_keys(client_random, server_random)
        client_decrypt_key = keys["client_decrypt_key"]
        log_connection(peer, "session_keys_derived", {
            "client_random_hash": (md5_short(client_random)),
        })

    # ---- Client Info PDU ----
    try:
        ci = await asyncio.wait_for(read_tpkt(reader), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        log_connection(peer, "client_info_timeout")
        return
    if len(ci) < 8:
        return
    mcs_payload = legacy.parse_send_data_request(ci[3:])
    if not mcs_payload:
        return

    flags, body = legacy.strip_security_header(mcs_payload)
    if encrypted and client_decrypt_key and (flags & 0x0008):
        try:
            body = legacy.rc4_decrypt(client_decrypt_key, body)
        except Exception as e:
            log_connection(peer, "rc4_fail", {"error": repr(e)})
            return

    creds = legacy.parse_client_info_pdu(body)
    if creds is None:
        log_connection(peer, "client_info_parse_fail",
                       {"len": len(body), "first": body[:32].hex()})
        return

    log_credentials(peer, {
        "captured_via": source,
        "username": creds.username,
        "domain": creds.domain,
        "password": creds.password,
        "workstation": "",
        "alternate_shell": creds.alternate_shell,
        "working_dir": creds.working_dir,
        "unicode": creds.is_unicode,
    })

    # Закрываем соединение — клиент увидит "сервер прервал сессию".


def md5_short(b: bytes) -> str:
    from hashlib import md5
    return md5(b).hexdigest()[:12]


# ====================================================================
#                  ASN.1 helpers для CredSSP TSRequest
# ====================================================================

def _asn1_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b"\x81" + bytes([n])
    if n < 0x10000:
        return b"\x82" + struct.pack(">H", n)
    return b"\x83" + struct.pack(">I", n)[1:]


def _asn1(tag, content):
    return bytes([tag]) + _asn1_len(len(content)) + content


def _asn1_integer(v):
    if v == 0:
        return _asn1(0x02, b"\x00")
    raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _asn1(0x02, raw)


def _wrap_tsrequest_with_ntlm(ntlm_token):
    version = _asn1(0xA0, _asn1_integer(6))
    nego_token = _asn1(0xA0, _asn1(0x04, ntlm_token))
    nego_tokens = _asn1(0xA1, _asn1(0x30, _asn1(0x30, nego_token)))
    return _asn1(0x30, version + nego_tokens)


def _build_credssp_error():
    version = _asn1(0xA0, _asn1_integer(6))
    error_code = _asn1(0xA4, _asn1_integer(0xC000006D))
    return _asn1(0x30, version + error_code)


# ====================================================================
#                                 main
# ====================================================================

async def amain():
    global LEGACY_KEY
    _ensure_certificate()
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    log.info("Генерация серверного RSA 2048 для legacy-ветки...")
    LEGACY_KEY = LegacyServerKey()
    log.info("RSA 2048 готов (modulus %d байт)", LEGACY_KEY.modulus_byte_len)

    server = await asyncio.start_server(
        handle_client, HOST, PORT,
        family=socket.AF_INET, reuse_address=True,
    )
    log.info(
        "RDP honeypot слушает %s:%d (computer=%s domain=%s force_legacy=%s)",
        HOST, PORT, NETBIOS_COMPUTER, NETBIOS_DOMAIN, FORCE_LEGACY_DOWNGRADE,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        sys.exit(0)
