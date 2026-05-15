"""
Legacy "Standard RDP Security" — реализация серверной стороны
для случая, когда клиент откатывается на PROTOCOL_RDP (без TLS/NLA).

Зачем: в этой ветке клиент шлёт пароль **в открытом виде** (после RC4
с сессионным ключом, который мы знаем) — в Client Info PDU.

Реализованы:
  * парсинг MCS Connect Initial (вытаскиваем CS_CORE/CS_SECURITY/CS_NET)
  * сборка MCS Connect Response с serverCoreData/serverSecurityData
    (включая Proprietary Certificate с нашим server RSA pubkey,
    подписанным well-known TS-ключом) + serverNetworkData
  * Erect Domain (без ответа), Attach User Confirm, Channel Join Confirm
  * парсинг Security Exchange PDU → расшифровка ClientRandom
  * KDF [MS-RDPBCGR 5.3.5.1] → SessionKeyBlob → ClientDecryptKey
  * RC4 + парсинг Client Info PDU → plaintext domain/user/password

Ссылка: [MS-RDPBCGR] 2.2.1.4, 5.3.3, 5.3.4, 5.3.5
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from hashlib import md5, sha1

from cryptography.hazmat.primitives.ciphers import Cipher

try:
    # cryptography >= 43: ARC4 переехал в decrepit
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

from ts_signing_key import TSSK_MODULUS, TSSK_PUBLIC_EXPONENT, ts_sign


# ----------------- константы MCS / GCC user data -----------------

# server user data header types ([MS-RDPBCGR] 2.2.1.4)
SC_CORE = 0x0C01
SC_SECURITY = 0x0C02
SC_NET = 0x0C03

# Encryption method
ENCRYPTION_METHOD_128BIT = 0x00000002
ENCRYPTION_LEVEL_CLIENT_COMPATIBLE = 0x00000002


# ----------------- упрощённый BER парсер для MCS Connect Initial -----------------

def find_gcc_user_data_block(payload: bytes, block_type: int) -> bytes | None:
    """
    В MCS Connect Initial userData блоки идут друг за другом, формат:
        type (LE u16) | length (LE u16) | data
    Перебираем и ищем нужный тип. Не разбираем BER-обёртку — просто
    сканируем по сигнатурам типов (CS_CORE = 0x01 0xC0 в little-endian).
    """
    # Тип в little-endian, например CS_CORE = 0xC001 → bytes b"\x01\xc0"
    type_bytes = struct.pack("<H", block_type)
    # Найдём вхождение, проверим, что length sane
    i = 0
    while i < len(payload) - 4:
        idx = payload.find(type_bytes, i)
        if idx < 0:
            return None
        if idx + 4 > len(payload):
            return None
        length = struct.unpack("<H", payload[idx + 2 : idx + 4])[0]
        if 4 <= length <= 0x400 and idx + length <= len(payload):
            return payload[idx : idx + length]
        i = idx + 1
    return None


# ----------------- сборка Proprietary Certificate + server RSA pubkey -----------------

def build_proprietary_certificate(
    modulus_le: bytes,    # 256 байт (2048-bit) либо 64 (512-bit)
    public_exp: int,
) -> bytes:
    """
    Серверный self-signed proprietary certificate
    [MS-RDPBCGR 2.2.1.4.3.1.1].

    Формат:
        dwVersion            (4)  = 1
        dwSigAlgId           (4)  = 1
        dwKeyAlgId           (4)  = 1
        wPublicKeyBlobType   (2)  = 0x0006 (BB_RSA_KEY_BLOB)
        wPublicKeyBlobLen    (2)
        PublicKeyBlob        (variable)  -- см. RSA_PUBLIC_KEY
        wSignatureBlobType   (2)  = 0x0008 (BB_RSA_SIGNATURE_BLOB)
        wSignatureBlobLen    (2)
        SignatureBlob        (variable)  -- 64+8 байт
    """
    # RSA_PUBLIC_KEY:
    #   magic (4)            = 0x31415352 "RSA1"
    #   keylen (4)           = len(modulus) + 8  (modulus + 8 trailing zeros)
    #   bitlen (4)           = len(modulus) * 8
    #   datalen (4)          = bitlen / 8 - 1
    #   pubExp (4)           = e (LE)
    #   modulus (keylen)     = modulus_le || 8*\x00
    keylen = len(modulus_le) + 8
    bitlen = len(modulus_le) * 8
    datalen = bitlen // 8 - 1
    pub_key_blob = (
        struct.pack("<IIIII",
                    0x31415352,  # "RSA1"
                    keylen,
                    bitlen,
                    datalen,
                    public_exp)
        + modulus_le
        + b"\x00" * 8
    )

    # CERT_INFO для подписи: всё что выше PublicKeyBlob (включая его)
    # — а именно: dwVersion..wPublicKeyBlobLen || PublicKeyBlob
    cert_info_prefix = struct.pack(
        "<IIIHH",
        1,      # dwVersion = 1 (proprietary)
        1,      # dwSigAlgId = 1
        1,      # dwKeyAlgId = 1
        0x0006, # wPublicKeyBlobType
        len(pub_key_blob),
    ) + pub_key_blob

    signature = ts_sign(cert_info_prefix)  # 64 байта
    signature += b"\x00" * 8               # padding до 72

    return cert_info_prefix + struct.pack(
        "<HH",
        0x0008,  # wSignatureBlobType
        len(signature),
    ) + signature


def build_server_security_data(
    server_random: bytes,
    modulus_le: bytes,
    public_exp: int,
) -> bytes:
    """
    SC_SECURITY (UD_SC_SEC1) block [MS-RDPBCGR 2.2.1.4.3].
    """
    assert len(server_random) == 32
    cert = build_proprietary_certificate(modulus_le, public_exp)
    body = (
        struct.pack(
            "<II",
            ENCRYPTION_METHOD_128BIT,
            ENCRYPTION_LEVEL_CLIENT_COMPATIBLE,
        )
        + struct.pack("<I", len(server_random))     # serverRandomLen
        + struct.pack("<I", len(cert))              # serverCertLen
        + server_random
        + cert
    )
    return struct.pack("<HH", SC_SECURITY, len(body) + 4) + body


def build_server_core_data() -> bytes:
    """SC_CORE: version = 0x00080004 (RDP 5.x — выглядит как 2008/2012)."""
    body = struct.pack(
        "<II",
        0x00080004,    # version
        0x00000000,    # clientRequestedProtocols (0 = legacy)
    )
    return struct.pack("<HH", SC_CORE, len(body) + 4) + body


def build_server_network_data(channels: list[int]) -> bytes:
    """
    SC_NET — список ID виртуальных каналов. Нам реально каналы не нужны,
    выдадим IO channel + по одному каналу на каждый запрошенный.
    """
    # MCSChannelID I/O = 1003, и далее по одному ID на каждый запрос
    io_channel = 1003
    body = struct.pack("<HH", io_channel, len(channels))
    for i, _ in enumerate(channels):
        body += struct.pack("<H", 1004 + i)
    # padding до 4 байт
    while len(body) % 4 != 0:
        body += b"\x00"
    return struct.pack("<HH", SC_NET, len(body) + 4) + body


# ----------------- MCS Connect Response -----------------

def build_mcs_connect_response(
    server_random: bytes,
    modulus_le: bytes,
    public_exp: int,
    requested_channels_count: int,
) -> bytes:
    """
    Собирает MCS Connect Response (BER-encoded) с GCC ConferenceCreateResponse,
    в котором лежат SC_CORE + SC_SECURITY + SC_NET.

    Это работа с BER — используем шаблон с подстановкой длины GCC user data.
    """
    user_data = (
        build_server_core_data()
        + build_server_network_data(list(range(requested_channels_count)))
        + build_server_security_data(server_random, modulus_le, public_exp)
    )

    # GCC ConferenceCreateResponse (PER-encoded, MS-RDPBCGR 2.2.1.4)
    # Шаблон с зашитыми константами + длина user_data в конце.
    # Используем "h221Key" константы (как у Windows).
    gcc_ccr = (
        b"\x00\x05\x00\x14\x7c\x00\x01"      # T.124 header
        + _per_length(len(user_data) + 16) + b""  # see below
    )

    # Полная фрагментация PER:
    # Реальный пакет, как формирует Windows:
    h221_key = b"McDn"                       # "Microsoft Display Name" / server-side h221key
    gcc_body = (
        b"\x00\x05"                          # nodeID = 0x79f3 +0x4d61? нет это просто константа
        b"\x14\x7c\x00\x01"                  # T.124 PER prefix
    )
    # Сделаем проще: используем готовый шаблон и в конце ставим user_data.
    # Шаблон взят из дампа реальной Windows-сессии (BER длины пересчитываем).

    # PER-кодированный user_data prefix + h221 key "McDn"
    user_data_full = (
        b"\x00\x05\x00\x14\x7c\x00\x01"      # T.124 ConnectData PDU header
        + _ber_long_length(len(user_data) + 14)  # connectPDUlen
        + b"\x2a\x14\x76\x0a\x01\x01\x00\x01\xc0\x00"
        b"\x4d\x63\x44\x6e"                  # "McDn" h221 server key
        + _per_length_user_data(len(user_data))
        + user_data
    )

    # Внешний MCS Connect-Response (BER):
    #   ConnectMCSPDU choice = connect-response (TAG 0x7F 0x66)
    #   sequence:
    #     result            ENUMERATED   = 0 (rt-successful)         tag 0x0A 0x02
    #     calledConnectId   INTEGER      = 0                          tag 0x02 0x01
    #     domainParameters  SEQUENCE     (стандартные значения)
    #     userData          OCTET STRING (user_data_full)
    mcs_connect_response = (
        b"\x0a\x01\x00"                              # result = 0
        b"\x02\x01\x00"                              # calledConnectId = 0
        # domainParameters SEQUENCE длиной 26 байт:
        b"\x30\x1a"
        b"\x02\x01\x22"                              # maxChannelIds = 34
        b"\x02\x01\x02"                              # maxUserIds = 2
        b"\x02\x01\x00"                              # maxTokenIds = 0
        b"\x02\x01\x01"                              # numPriorities = 1
        b"\x02\x01\x00"                              # minThroughput = 0
        b"\x02\x01\x01"                              # maxHeight = 1
        b"\x02\x02\xff\xff"                          # maxMCSPDUsize = 65535
        b"\x02\x01\x02"                              # protocolVersion = 2
        b"\x04"                                       # userData OCTET STRING tag
        + _ber_length(len(user_data_full))
        + user_data_full
    )

    # Внешняя BER application 102 (0x7F 0x66) обёртка
    outer = (
        b"\x7f\x66"
        + _ber_length(len(mcs_connect_response))
        + mcs_connect_response
    )
    return outer


def _ber_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82]) + struct.pack(">H", n)
    return bytes([0x83]) + struct.pack(">I", n)[1:]


def _ber_long_length(n: int) -> bytes:
    """Variant: always 2-byte length (PER encoding в GCC обычно)."""
    return struct.pack(">H", n | 0x8000)


def _per_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    return struct.pack(">H", n | 0x8000)


def _per_length_user_data(n: int) -> bytes:
    """User data length в PER: 14-bit value с флагом 0x80."""
    return struct.pack(">H", n | 0x8000)


# ----------------- Erect Domain / Attach User / Channel Join -----------------

def build_attach_user_confirm(user_id: int = 1001) -> bytes:
    """
    MCS Attach-User-Confirm.
    PDU type = 11 (0x2E in choice index, encoded as 0x2E in lower 6 bits of first byte).
    Format:
        DomainMCSPDU choice = attach-user-confirm (high 6 bits = 0x2E)
        result ENUMERATED (3 bits) = 0
        initiator (optional bit + UserId = ChannelId - 1001)
    Полный байтовый дамп (как у Windows): 0x2E 0x00 0x00 0x03 0xE9
    """
    initiator = user_id - 1001
    # 0x2E = 0b001011_10 → choice index 11 (attach-user-confirm), shifted
    return bytes([
        0x2E,
        0x00 | 0x02,  # result = 0, initiator-present = 1
        0x00,
        ((1001 + initiator) >> 8) & 0xFF,
        (1001 + initiator) & 0xFF,
    ])


def build_channel_join_confirm(user_id: int, channel_id: int) -> bytes:
    """
    MCS Channel-Join-Confirm:
        choice = 15 (0x3E in upper 6 bits)
        result ENUMERATED = 0
        initiator UserID
        requested ChannelID
        channelId ChannelID
    """
    return bytes([
        0x3E,
        0x00,  # result = 0
        ((user_id) >> 8) & 0xFF, user_id & 0xFF,
        (channel_id >> 8) & 0xFF, channel_id & 0xFF,
        (channel_id >> 8) & 0xFF, channel_id & 0xFF,
    ])


def parse_mcs_pdu_type(data: bytes) -> int:
    """Возвращает choice index (старшие 6 бит первого байта >> 2)."""
    if not data:
        return -1
    return data[0] >> 2


MCS_ERECT_DOMAIN_REQUEST = 1
MCS_ATTACH_USER_REQUEST = 10
MCS_CHANNEL_JOIN_REQUEST = 14
MCS_SEND_DATA_REQUEST = 25


def parse_channel_join_request(data: bytes) -> tuple[int, int]:
    """Возвращает (user_id, channel_id) из Channel-Join-Request."""
    # Format: 0x38 (choice 14 << 2) | userId(2) | channelId(2)
    if len(data) < 5:
        return 0, 0
    user_id = struct.unpack(">H", data[1:3])[0]
    channel_id = struct.unpack(">H", data[3:5])[0]
    return user_id, channel_id


# ----------------- Send Data Request (где едут Security Exchange / Client Info) -----------------

def parse_send_data_request(data: bytes) -> bytes | None:
    """
    Send Data Request layout:
        choice (1)
        initiator UserID (2)
        channelId ChannelID (2)
        dataPriority + segmentation (1)
        userData length-PER (1 or 2)
        userData
    Возвращает userData (payload поверх MCS).
    """
    if len(data) < 8 or parse_mcs_pdu_type(data) != MCS_SEND_DATA_REQUEST:
        return None
    # length может быть 1 или 2 байта PER
    length_byte = data[7]
    if length_byte & 0x80:
        # 2 байта
        length = ((length_byte & 0x7F) << 8) | data[8]
        return data[9 : 9 + length]
    else:
        length = length_byte
        return data[8 : 8 + length]


# ----------------- Security Exchange PDU -----------------

def parse_security_exchange(payload: bytes) -> bytes | None:
    """
    Внутри Send Data Request лежит Security Header (4 байта flags) +
    SecurityExchange PDU:
        length (4)         -- длина encrypted client random + 8
        encryptedClientRandom (length - 8)
        padding (8)

    Возвращает зашифрованный client_random (little-endian как есть).
    """
    if len(payload) < 8:
        return None
    flags = struct.unpack("<H", payload[0:2])[0]
    if not (flags & 0x0001):  # SEC_EXCHANGE_PKT = 0x0001
        return None
    # пропускаем 4 байта security header
    length = struct.unpack("<I", payload[4:8])[0]
    if length < 8 or len(payload) < 8 + length:
        return None
    return payload[8 : 8 + length - 8]  # без 8 байт trailing padding


def decrypt_client_random(
    encrypted_le: bytes,
    server_private_exp_int: int,
    server_modulus_int: int,
    modulus_byte_len: int,
) -> bytes:
    """
    Raw RSA decrypt (little-endian, как в MS-RDPBCGR).
    Возвращает 32-байтный client_random.
    """
    c = int.from_bytes(encrypted_le, "little")
    m = pow(c, server_private_exp_int, server_modulus_int)
    plain = m.to_bytes(modulus_byte_len, "little")
    return plain[:32]


# ----------------- KDF (MS-RDPBCGR 5.3.5.1) -----------------

def _salted_hash(s: bytes, i: bytes, client_random: bytes, server_random: bytes) -> bytes:
    return md5(s + sha1(i + s + client_random + server_random).digest()).digest()


def _final_hash(k: bytes, client_random: bytes, server_random: bytes) -> bytes:
    return md5(k + client_random + server_random).digest()


def derive_keys(client_random: bytes, server_random: bytes) -> dict[str, bytes]:
    """
    Возвращает dict с:
      master_secret (48 байт)
      session_key_blob (48 байт)
      client_encrypt_key  — клиент шифрует им свои сообщения серверу
      client_decrypt_key  — сервер расшифровывает им сообщения от клиента (== client_encrypt_key)
    """
    pre_master = client_random[:24] + server_random[:24]
    master_secret = (
        _salted_hash(pre_master, b"A", client_random, server_random)
        + _salted_hash(pre_master, b"BB", client_random, server_random)
        + _salted_hash(pre_master, b"CCC", client_random, server_random)
    )
    skb = (
        _salted_hash(master_secret, b"X", client_random, server_random)
        + _salted_hash(master_secret, b"YY", client_random, server_random)
        + _salted_hash(master_secret, b"ZZZ", client_random, server_random)
    )
    # Для 128-bit RC4 ([MS-RDPBCGR] 5.3.5.1 — Decryption Key + Encryption Key):
    client_decrypt_key = _final_hash(skb[16:32], client_random, server_random)
    return {
        "master_secret": master_secret,
        "session_key_blob": skb,
        "client_decrypt_key": client_decrypt_key,  # серверный decrypt = клиентский encrypt
    }


# ----------------- RC4 -----------------

def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = Cipher(ARC4(key), mode=None).decryptor()
    return cipher.update(data) + cipher.finalize()


# ----------------- Client Info PDU -----------------

@dataclass
class ClientCredentials:
    domain: str
    username: str
    password: str
    alternate_shell: str
    working_dir: str
    is_unicode: bool


def parse_client_info_pdu(plaintext: bytes) -> ClientCredentials | None:
    """
    Структура [MS-RDPBCGR 2.2.1.11.1.1]:
        CodePage              (4)
        flags                 (4)
        cbDomain              (2)
        cbUserName            (2)
        cbPassword            (2)
        cbAlternateShell      (2)
        cbWorkingDir          (2)
        Domain                (cbDomain + 2 null terminator)
        UserName              (cbUserName + 2)
        Password              (cbPassword + 2)
        AlternateShell        (cbAlternateShell + 2)
        WorkingDir            (cbWorkingDir + 2)
    """
    if len(plaintext) < 18:
        return None
    flags = struct.unpack("<I", plaintext[4:8])[0]
    is_unicode = bool(flags & 0x00000010)  # INFO_UNICODE

    cb_domain = struct.unpack("<H", plaintext[8:10])[0]
    cb_user = struct.unpack("<H", plaintext[10:12])[0]
    cb_pass = struct.unpack("<H", plaintext[12:14])[0]
    cb_alt = struct.unpack("<H", plaintext[14:16])[0]
    cb_wd = struct.unpack("<H", plaintext[16:18])[0]

    # Null terminator: UNICODE → 2 байта, ANSI → 1
    nt_size = 2 if is_unicode else 1

    offset = 18

    def take(cb: int) -> str:
        nonlocal offset
        end = offset + cb + nt_size
        if end > len(plaintext):
            return ""
        chunk = plaintext[offset : offset + cb]
        offset = end
        if is_unicode:
            return chunk.decode("utf-16-le", errors="replace")
        return chunk.decode("latin-1", errors="replace")

    try:
        domain = take(cb_domain)
        user = take(cb_user)
        password = take(cb_pass)
        alt_shell = take(cb_alt)
        working_dir = take(cb_wd)
    except Exception:
        return None

    return ClientCredentials(
        domain=domain,
        username=user,
        password=password,
        alternate_shell=alt_shell,
        working_dir=working_dir,
        is_unicode=is_unicode,
    )


# ----------------- security header (для Send Data after Security Exchange) -----------------

def strip_security_header(payload: bytes) -> tuple[int, bytes]:
    """
    Возвращает (flags, data_after_header).
    Если SEC_ENCRYPT флаг → ещё 8 байт MAC после flags.
    """
    if len(payload) < 4:
        return 0, b""
    flags = struct.unpack("<H", payload[0:2])[0]
    # flagsHi (2) — обычно 0
    if flags & 0x0008:  # SEC_ENCRYPT
        # 8 байт data signature
        return flags, payload[12:]
    return flags, payload[4:]


# ----------------- MCS Connect Initial parsing helpers -----------------

def parse_cs_net_channel_names(net_block: bytes) -> list[str]:
    """
    Extract virtual channel names from CS_NET GCC block.
    Format (MS-RDPBCGR 2.2.1.3.4):
        type(2) | length(2) | channelCount(4) | [name(8) + options(4)] * N
    """
    if not net_block or len(net_block) < 8:
        return []
    try:
        count = struct.unpack("<I", net_block[4:8])[0]
        if count > 64 or 8 + count * 12 > len(net_block):
            return []
        names = []
        for i in range(count):
            off = 8 + i * 12
            raw = net_block[off : off + 8]
            name = raw.rstrip(b"\x00").decode("ascii", errors="replace").strip()
            if name:
                names.append(name)
        return names
    except Exception:
        return []


def parse_cs_core_client_build(core_block: bytes) -> int:
    """
    Extract clientBuild from CS_CORE block (MS-RDPBCGR 2.2.1.3.2).
    Layout: type(2) + length(2) + version(4) + desktopWidth(2) +
            desktopHeight(2) + colorDepth(2) + SASSeq(2) +
            keyboardLayout(4) + clientBuild(4) → offset 20.
    """
    if not core_block or len(core_block) < 24:
        return 0
    try:
        return struct.unpack("<I", core_block[20:24])[0]
    except Exception:
        return 0
