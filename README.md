# RDP Honeypot

> Самописный RDP-honeypot на Python, имитирующий **Windows Server 2008 R2** на уровне протокола.  
> Захватывает **plaintext-пароли** от legacy-клиентов/ботов и **NetNTLMv2-хеши** от NLA-клиентов.

---

## Как это работает

Большинство интернет-ботов и брутфорс-инструментов (hydra, ncrack, medusa, crowbar) при сканировании порта 3389 используют **legacy Standard RDP Security** без TLS. В этом режиме Windows-сервер отдаёт Proprietary Certificate и обменивается RC4-зашифрованным Client Info PDU, внутри которого — домен, имя пользователя и **пароль в открытом виде**.

Honeypot реализует полный протокольный стек этой ветки, поэтому клиент «верит» серверу и честно отдаёт пароль.

### Гибридная стратегия (по умолчанию)

```
Клиент → PROTOCOL_HYBRID (NLA/CredSSP)
Server ← NEG_FAILURE = SSL_NOT_ALLOWED_BY_SERVER
  │
  └─ большинство ботов делают retry с PROTOCOL_RDP
       Клиент → PROTOCOL_RDP (legacy)
       Server ← MCS Connect Response + Proprietary Certificate
       Клиент → Security Exchange (зашифрованный ClientRandom)
       Server  расшифровывает, выводит RC4 session keys
       Клиент → Client Info PDU (зашифрован RC4)
       Server  расшифровывает → domain / user / PASSWORD в открытом виде ✓
```

| Что запросил клиент | Ответ сервера | Что получаем |
|---|---|---|
| `PROTOCOL_RDP` | MCS → RSA → RC4 → Client Info | **plaintext пароль** |
| `PROTOCOL_SSL` (без NLA) | TLS → Client Info | **plaintext пароль** |
| `PROTOCOL_HYBRID` + downgrade | NEG_FAILURE → ждём retry | зависит от клиента |
| `PROTOCOL_HYBRID` + `FORCE_LEGACY=0` | TLS → CredSSP NTLMSSP | **NetNTLMv2 hash** (-m 5600) |

---

## Реализованный протокольный стек

- **TPKT** (RFC 1006) + **X.224** (ITU-T X.224 Class 0)
- **RDP_NEG_REQ / RDP_NEG_RSP / RDP_NEG_FAILURE** (MS-RDPBCGR 2.2.1.1.1)
- **MCS Connect Initial / Response** (T.125 + GCC ConferenceCreateResponse)
- **Proprietary Certificate** с подписью well-known Terminal Services RSA-key (MS-RDPBCGR 5.3.3.1)
- **Security Exchange PDU** → RSA raw decrypt → ClientRandom
- **KDF по MS-RDPBCGR 5.3.5.1** (SHA1 + MD5 salt chain) → 128-bit RC4 session keys
- **RC4 decrypt** Client Info PDU → plaintext domain/user/password
- **CredSSP / NTLMSSP** server-side: NEGOTIATE → CHALLENGE (с AV_PAIRs: NetBIOS/DNS/TIMESTAMP) → AUTHENTICATE → NetNTLMv2 hashcat-format
- **TLS self-signed сертификат** (CN=WIN-SRV2008, RSA-2048 SHA-256, 10 лет, SAN)

Fingerprint при nmap `--script rdp-ntlm-info`:
```
Product_Version: 6.1.7601    ← Windows Server 2008 R2 SP1
NetBIOS_Computer_Name: WIN-SRV2008
NetBIOS_Domain_Name: CORP
DNS_Domain_Name: corp.local
```

---

## Структура

```
rdp-honeypot/
├── docker-compose.yml
├── .env.example
├── honeypot/
│   ├── Dockerfile
│   ├── requirements.txt        # cryptography
│   ├── supervisord.conf        # supervisord: honeypot + log_loop
│   ├── log_loop.sh             # запускает log_processor каждые 60 сек
│   ├── honeypot.py             # asyncio TCP-сервер, маршрутизация по протоколу
│   ├── rdp_protocol.py         # TPKT, X.224, RDP_NEG_REQ/RSP
│   ├── rdp_legacy.py           # MCS, Proprietary Cert, KDF, RC4, Client Info
│   ├── ts_signing_key.py       # well-known TS RSA signing key (FreeRDP)
│   └── ntlm.py                 # NTLMSSP CHALLENGE/AUTHENTICATE + hashcat
└── scripts/
    └── log_processor.py        # JSONL → публичный/приватный лог
```

---

## Установка

### Требования

- **Docker + docker compose v2** (или docker-compose v1)
- Свободный порт 3389/tcp

Systemd, Python и iptables на хосте **не нужны** — всё работает внутри контейнера.

### Быстрый старт

```bash
git clone https://github.com/robulanetteam/rdp_honeypot
cd rdp_honeypot
docker compose up -d
```

Готово. Контейнер поднимается с дефолтными настройками без `.env`.

Для кастомизации:
```bash
cp .env.example .env   # отредактируйте под себя
docker compose up -d
```

Данные на хосте после запуска:
```
./data/logs/       — JSONL события + TLS-сертификат
./data/public/     — публичный лог (раздавайте через nginx/caddy)
./data/private/    — credentials.log с паролями и hash-строками
```

### Автостарт

DockerEngine сам перезапустит контейнер (`restart: unless-stopped`).
Для запуска при старте системы достаточно, чтобы `docker` был в автостарте:

```bash
systemctl enable docker   # один раз
```

---

## Конфигурация

Все переменные передаются через `.env` (или `environment:` в `docker-compose.yml`).
Без `.env` контейнер запускается с разумными дефолтами.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `HONEYPOT_COMPUTER` | `WIN-SRV2008` | NetBIOS-имя машины |
| `HONEYPOT_DOMAIN` | `CORP` | NetBIOS-домен |
| `HONEYPOT_DNS_COMPUTER` | `WIN-SRV2008.corp.local` | DNS-имя |
| `HONEYPOT_DNS_DOMAIN` | `corp.local` | DNS-домен |
| `HONEYPOT_FORCE_LEGACY` | `1` | Форсировать downgrade на legacy RDP (plaintext) |
| `TZ` | `Europe/Moscow` | Часовой пояс для меток в логах |
| `PUBLIC_LOG_NAME` | `rdp_honeypot.txt` | Имя файла в `./data/public/` |
| `PUBLIC_LOG_EVERY_N` | `3` | Каждая N-я попытка с IP → публичный лог |
| `WINDOW_HOURS` | `24` | Окно учёта попыток (часов) |

---

## Логи

### `data/logs/connections.jsonl`

Каждое событие соединения (JSONL):
```json
{"timestamp":"2026-05-13T14:00:01+03:00","logger":"mitm.connections",
 "source_ip":"1.2.3.4","source_port":54321,"stage":"tcp_accept"}
{"stage":"x224_cr","cookie":"mstshash=user","requested_protocols":"0x00000000"}
{"stage":"session_keys_derived","client_random_hash":"a1b2c3d4e5f6"}
```

### `data/logs/credentials.jsonl`

Захваченные учётные данные:
```json
{
  "timestamp": "2026-05-13T14:00:02+03:00",
  "source_ip": "1.2.3.4",
  "captured_via": "legacy_rdp",
  "domain": "WORKGROUP",
  "username": "Administrator",
  "password": "Passw0rd123!"
}
```

Или для NLA-ветки:
```json
{
  "captured_via": "nla_ntlmssp",
  "username": "admin",
  "domain": "CORP",
  "ntlm_version": "v2",
  "hashcat": "admin::CORP:aabbccdd...:112233...:0102..."
}
```

### Публичный и приватный логи

`log_processor.py` запускается **внутри контейнера** через `supervisord` раз в минуту (`log_loop.sh`):
- **Публичный** — `./data/public/$PUBLIC_LOG_NAME`: каждая N-я попытка с IP как строка вида `2026-05-13 14:00 | 1.2.3.4 | attempt #3 in last 24h`
- **Приватный** — `./data/private/credentials.log` (монтируйте с `chmod 0700` на хосте): все пары логин/пароль или hashcat-строки

---

## Проверка маскировки

```bash
# nmap — должно выдать Windows Server 2008 R2
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info <IP>

# Симуляция брутфорса (hydra)
hydra -l Administrator -p test <IP> rdp

# Shodan-like banner
masscan <IP> -p 3389 --banners
```

---

## Защита

- Docker: dropped ALL capabilities, только `NET_BIND_SERVICE`, `no-new-privileges`
- Приватный лог никогда не попадает в публичный каталог
- TLS-ключ генерируется один раз при старте контейнера и хранится в volume
- Для iptables rate-limit (опционально): `iptables -I INPUT -p tcp --dport 3389 -m limit --limit 5/min -j ACCEPT && iptables -A INPUT -p tcp --dport 3389 -j DROP`

---

## Дисклеймер

Используйте только на **оборудовании, которое вам принадлежит**, или с явного письменного разрешения владельца. Несанкционированный перехват учётных данных является уголовно наказуемым во многих юрисдикциях. Авторы не несут ответственности за любое незаконное использование.

Этот инструмент предназначен исключительно для:
- исследований собственной инфраструктуры (threat hunting / honeypot)
- изучения IOC и тактик атакующих
- академических и CTF-целей
