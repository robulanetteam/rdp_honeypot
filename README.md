# RDP Honeypot

Самописный RDP-listener на Python, имитирующий **Windows Server 2008 R2**.  
Захватывает **plaintext-пароли** от legacy-клиентов и **NetNTLMv2-хеши** от NLA-клиентов.

---

## Как это работает

Большинство интернет-ботов при сканировании порта 3389 используют **legacy Standard RDP Security** без TLS. В этом режиме клиент обменивается RC4-зашифрованным Client Info PDU, содержащим домен, имя пользователя и **пароль в открытом виде**.

Honeypot реализует полный протокольный стек этой ветки — клиент «верит» серверу и отдаёт пароль.

### Гибридная стратегия (по умолчанию, `HONEYPOT_FORCE_LEGACY=1`)

```
Клиент → PROTOCOL_HYBRID (NLA/CredSSP)
Server  → NEG_FAILURE (SSL_NOT_ALLOWED_BY_SERVER)
            ↓ большинство ботов делают retry
Клиент → PROTOCOL_RDP
Server  → MCS + Proprietary Certificate + RC4
Клиент → Client Info PDU (RC4)
Server  → расшифровывает → domain / user / PASSWORD ✓
```

| Запрос клиента | Ответ | Результат |
|---|---|---|
| `PROTOCOL_RDP` | MCS → RC4 → Client Info | **plaintext пароль** |
| `PROTOCOL_SSL` | TLS → Client Info | **plaintext пароль** |
| `PROTOCOL_HYBRID` + `FORCE_LEGACY=1` | NEG_FAILURE → retry | plaintext после downgrade |
| `PROTOCOL_HYBRID` + `FORCE_LEGACY=0` | TLS → NTLMSSP | **NetNTLMv2 hash** (hashcat -m 5600) |

---

## Структура

```
rdp_honeypot/
├── docker-compose.yml
├── .env.example
├── honeypot/
│   ├── Dockerfile
│   ├── requirements.txt        # cryptography
│   ├── supervisord.conf        # запускает honeypot + log_loop
│   ├── log_loop.sh             # log_processor каждые 60 сек
│   ├── honeypot.py             # asyncio TCP-сервер
│   ├── rdp_protocol.py         # TPKT, X.224, RDP_NEG
│   ├── rdp_legacy.py           # MCS, Proprietary Cert, KDF, RC4
│   ├── ts_signing_key.py       # well-known TS RSA signing key
│   └── ntlm.py                 # NTLMSSP + hashcat output
└── scripts/
    ├── log_processor.py        # JSONL → публичный/приватный лог + аналитика
    └── classifier.py           # классификатор IP: scanner / bruteforcer / accidental
```

---

## Запуск

**Требования:** Docker + docker compose v2. Больше ничего.

```bash
git clone https://github.com/robulanetteam/rdp_honeypot
cd rdp_honeypot
docker compose up -d
```

Без `.env` контейнер стартует с дефолтными настройками. Для кастомизации:

```bash
cp .env.example .env
# отредактируйте .env
docker compose up -d
```

Данные на хосте:
```
./data/logs/      — JSONL события + TLS-сертификат
./data/public/    — публичный лог (раздавайте через nginx/caddy)
./data/private/   — credentials.log с паролями и hash-строками
```

Автостарт — через Docker Engine (`restart: unless-stopped`):
```bash
systemctl enable docker
```

---

## Конфигурация

| Переменная | По умолчанию | Описание |
|---|---|---|
| `HONEYPOT_COMPUTER` | `WIN-SRV2008` | NetBIOS-имя |
| `HONEYPOT_DOMAIN` | `CORP` | NetBIOS-домен |
| `HONEYPOT_DNS_COMPUTER` | `WIN-SRV2008.corp.local` | DNS-имя |
| `HONEYPOT_DNS_DOMAIN` | `corp.local` | DNS-домен |
| `HONEYPOT_FORCE_LEGACY` | `1` | `1` = downgrade на legacy RDP (plaintext), `0` = NLA (hash) |
| `TZ` | `Europe/Moscow` | Часовой пояс |
| `PUBLIC_LOG_NAME` | `rdp_honeypot.txt` | Имя файла в `./data/public/` |
| `PUBLIC_LOG_EVERY_N` | `3` | Каждая N-я попытка с IP → публичный лог |
| `WINDOW_HOURS` | `24` | Окно учёта попыток (часов) |

---

## Логи

`./data/logs/credentials.jsonl` — захваченные данные:

```json
{"timestamp":"2026-05-13T14:00:02+03:00","source_ip":"1.2.3.4",
 "captured_via":"legacy_rdp","domain":"WORKGROUP",
 "username":"Administrator","password":"Passw0rd123!"}
```

```json
{"captured_via":"nla_ntlmssp","username":"admin","domain":"CORP",
 "ntlm_version":"v2","hashcat":"admin::CORP:aabb...:1122...:0102..."}
```

`log_processor.py` (supervisord, раз в минуту):
- `./data/public/rdp_honeypot.txt` — каждая N-я попытка с тегом класса: `2026-05-13 14:00 | 1.2.3.4 | attempt #3 in last 24h | scanner`
- `./data/private/credentials.log` — все пароли и hashcat-строки
- `./data/logs/analytics.jsonl` — классификация каждого IP при изменении:

```json
{"timestamp":"2026-05-15T10:00:00+03:00","source_ip":"34.38.74.158",
 "classification":"scanner","confidence":"high",
 "reasons":["scanner_cookie","tls_direct_probe","hybrid_ex_protocol","rapid_multiconn:4x_in_17s"],
 "sessions_total":4,"protocols_seen":["0x00000003","0x0000000b"],
 "has_credentials":false}
```

**Классификатор** (`classifier.py`) использует сигналы сессии:

| Сигнал | Класс | Очки |
|---|---|---|
| Cookie содержит `nmap` / `masscan` / `zgrab` / `shodan` / `censys` | scanner | +5 |
| TPKT exception — прямой TLS-зонд | scanner | +3 |
| `PROTOCOL_HYBRID_EX` bit (0x08) в requested_protocols | scanner | +3 |
| ≥3 соединений за <120 сек | scanner | +2 |
| >2 разных requested_protocols | scanner | +1 |
| Учётные данные захвачены | bruteforcer | +10 |
| Дошёл до `RDP_LEGACY` | bruteforcer | +5 |
| Downgrade NEG_FAILURE → повторное подключение в legacy | bruteforcer | +3 |
| ≥5 сессий от IP | bruteforcer | +2 |

Результат: `scanner` / `bruteforcer` / `accidental` / `unknown`, confidence: `low` / `medium` / `high`.

---

## Дисклеймер

Используйте только на оборудовании, которым владеете, или с письменного разрешения владельца.  
Предназначен для: threat hunting, изучения тактик атакующих, CTF.
