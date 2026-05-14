# OpenVPN Server Dashboard

[English](README.md) | **Русский**

Мониторинг нескольких OpenVPN серверов с веб-интерфейсом.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)

## Возможности

- 🔐 **Токен-авторизация** (заголовок `Authorization: Bearer …`)
- Поддержка нескольких серверов
- Графики трафика (5 мин – 7 дней)
- Активные сессии в реальном времени
- Статистика пользователей с поиском/сортировкой
- 📊 **Сравнение трафика пользователей** (до 10 на одном графике, 6ч/24ч/7д)
- 📋 **Просмотр сессий пользователя** (активные и недавние)
- 🔎 **Анализ openvpn.log** (опционально): причины дисконнектов, неуспешные попытки авторизации, латентность TLS-handshake, счётчик renegotiation, live-tail событий
- Экспорт CSV/JSON (полная выборка, без тихого обрезания)
- Множественные сессии одного пользователя, корректная обработка переподключений
- Автомиграции схемы + retention/VACUUM

## Быстрый старт

```bash
git clone https://github.com/yourusername/openvpn-server-dashboard.git
cd openvpn-server-dashboard
mkdir -p data
make up
# Откройте http://localhost:80
```

## Конфигурация

Отредактируйте `docker-compose.yml`:

**Несколько серверов:**
```yaml
environment:
  # NAME:STATUS_FILE[:LOG_FILE], несколько серверов через ";"
  - SERVERS_CONFIG=office:/var/log/openvpn/status.log:/var/log/openvpn/openvpn.log;branch:/var/log/openvpn/branch-status.log:/var/log/openvpn/branch.log
```

**Один сервер:**
```yaml
environment:
  - OPENVPN_STATUS_FILE=/var/log/openvpn/openvpn-status.log
  - OPENVPN_LOG_FILE=/var/log/openvpn/openvpn.log    # опционально, включает разбор лога
```

`STATUS_FILE` — это периодический снапшот, который OpenVPN пишет директивой `status` (status-version 2). `LOG_FILE` — основной лог из `log` / `log-append`, его дашборд читает для детекта неудачных авторизаций, причин дисконнектов и метрик TLS-handshake. Если указать в обоих позициях один и тот же путь — дашборд откажется парсить (форматы файлов разные); оставьте третье поле пустым, если openvpn.log недоступен или не нужен.

### Конфиг OpenVPN

Обязательно:
```
status      /var/log/openvpn/openvpn-status.log
```

Дашборд автоматически распознаёт и парсит оба формата: `status-version 1` (legacy/default) и `status-version 2`. v2 несёт пару дополнительных колонок (Virtual IPv6, Username, Client ID, Peer ID, Cipher) — для новых установок чуть предпочтительнее, но и дефолтный v1 работает.

Рекомендуется (включает фичи на основе лога — auth-фейлы, причины дисконнекта, TLS-метрики):
```
log-append  /var/log/openvpn/openvpn.log
verb        3
```

`verb 1`/`2` не пишут нужные строки в лог; `verb 4+` тоже работает, но логов будет много. Файл лога должен быть смонтирован read-only в контейнер дашборда (в примере `docker-compose.yml` уже монтируется `/var/log/openvpn`).

## Авторизация

Дашборд поддерживает токен-авторизацию для безопасного доступа.

### Настройка токена

**Способ 1: Через docker-compose.yml (рекомендуется)**

```yaml
environment:
  - AUTH_ENABLED=true
  - AUTH_TOKEN=ваш-секретный-токен
```

**Способ 2: Генерация безопасного токена**

```bash
# Сгенерировать случайный безопасный токен
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Пример вывода: xJ8kP2mN5qR9sT4vW7yZ0aB3cD6eF1gH

# Добавить в docker-compose.yml:
- AUTH_TOKEN=xJ8kP2mN5qR9sT4vW7yZ0aB3cD6eF1gH
```

**Способ 3: Отключить авторизацию (не рекомендуется)**

```yaml
environment:
  - AUTH_ENABLED=false
```

### Первый вход

1. Запустить дашборд: `make up`
2. Проверить логи для авто-сгенерированного токена (если AUTH_TOKEN не задан):
   ```bash
   make logs | grep "Generated random token"
   ```
3. Открыть http://localhost:80
4. Ввести токен на странице входа
5. Токен сохранится в localStorage браузера

### Рекомендации по безопасности

- ✅ Всегда задавайте сильный `AUTH_TOKEN` в продакшене
- ✅ Используйте HTTPS (см. секцию SSL)
- ✅ Периодически меняйте токен
- ✅ Держите токен в секрете - не коммитьте в git
- ⚠️ При компрометации токена немедленно смените его

## Переменные окружения

| Переменная | По умолчанию | Описание |
|-----------|--------------|----------|
| `AUTH_ENABLED` | `true` | Включить/отключить авторизацию |
| `AUTH_TOKEN` | (авто-генерация) | Токен для доступа к дашборду |
| `UPDATE_INTERVAL` | `60` | Интервал сбора статистики, сек |
| `RETENTION_DAYS` | `90` | Хранение сессий (дни) |
| `TRAFFIC_HISTORY_RETENTION_DAYS` | `30` | Хранение данных для графиков (дни) |
| `DEFAULT_LIMIT` / `MAX_LIMIT` | `50` / `500` | Лимиты пагинации для `/api/user_stats` (не влияют на экспорт) |
| `LOG_PARSE_ENABLED` | `true` | Включить разбор основного лога OpenVPN (`openvpn.log`) |
| `LOG_PARSE_MAX_BYTES` | `10485760` | Максимум байт за один цикл парсинга (защита от огромного лога после ротации) |
| `LOG_EVENT_MATCH_WINDOW` | `180` | Окно (сек) для связки события из лога с сессией по `(server, ip, port)` |
| `TZ` | `UTC` | Таймзона контейнера. Не меняйте — все времена хранятся и сравниваются в UTC (совпадает с SQLite `CURRENT_TIMESTAMP`). |

## API

Все API endpoints (кроме `/api/login` и `/api/check_auth`) требуют заголовок авторизации:

```bash
Authorization: Bearer ВАШ_ТОКЕН
```

### Эндпоинты

- `POST /api/login` - Проверка токена и вход
- `GET /api/check_auth` - Проверка включена ли авторизация
- `GET /api/health` - Проверка состояния
- `GET /api/servers` - Список серверов
- `GET /api/summary` - Сводка
- `GET /api/active_sessions?server=NAME` - Активные сессии
- `GET /api/user_stats?server=NAME&limit=50&search=user` - Статистика
- `GET /api/traffic_chart?server=NAME&hours=24` - Данные графиков
- `GET /api/user_traffic_chart?users=user1,user2&hours=24` - Данные сравнения пользователей
- `GET /api/user_sessions/<username>?server=NAME` - Список сессий пользователя
- `GET /api/users_list?server=NAME` - Список всех пользователей
- `GET /api/auth_failures?server=NAME&hours=24&limit=200` - Неуспешные авторизации (из `openvpn.log`)
- `GET /api/recent_events?server=NAME&types=auth_failure,disconnect&limit=100` - Live-tail событий подключения
- `GET /api/export/sessions?format=csv` - Экспорт сессий
- `GET /api/export/users?format=json` - Экспорт пользователей

### Пример API запроса

```bash
curl -H "Authorization: Bearer ваш-токен" \
  http://localhost/api/summary
```

## Сравнение пользователей

Сравнение потребления трафика нескольких пользователей на одном графике.

### Как использовать

1. **Через выпадающий список**: выберите пользователей из "Add user to compare"
2. **Через таблицы**: кликните на имя пользователя в Active Sessions или User Statistics
3. **Просмотр сессий**: кликните на иконку 📋 рядом с именем для просмотра всех сессий
4. **Сравнение**: до 10 пользователей можно сравнивать одновременно

### Возможности

- График сравнения трафика в реальном времени
- Карточки статистики по каждому пользователю (скачано/загружено)
- Модальное окно с деталями сессий (активные + за последние 7 дней)
- Цветовая дифференциация
- Выбор периода (6ч, 24ч, 7д) — работает в пределах `TRAFFIC_HISTORY_RETENTION_DAYS`

## База данных

SQLite со следующими таблицами:

| Таблица | Назначение |
|---------|-----------|
| `sessions` | По одной строке на VPN-сессию (старт/конец, байты, адреса). В схеме v3 добавлены nullable-колонки `disconnect_reason`, `tls_handshake_ms`, `reneg_count`, заполняемые из `openvpn.log`. |
| `user_stats` | Агрегированные счётчики по каждому пользователю (сессии, время, байты). |
| `traffic_history` | **Дельты** трафика для графиков. Строки с `username IS NULL` — агрегат для главного графика, с `username IS NOT NULL` — для графика сравнения. |
| `session_traffic_state` | Последние известные кумулятивные счётчики байт по каждой активной сессии; используются для вычисления дельт между циклами сбора. Обновляются каждый цикл, удаляются при отключении. |
| `connection_events` | Append-only журнал событий из `openvpn.log` (`auth_failure`, `verify_error`, `tls_error`, `peer_init`, `reneg`, `disconnect`, `inactivity`). Та же retention, что и у `traffic_history`. |
| `log_parse_state` | Per-server byte offset / inode основного лога OpenVPN, чтобы парсинг был инкрементальным и переживал рестарты/ротацию. |
| `schema_version` | Однострочная служебная таблица с текущей версией схемы (сейчас `3`). |

**Учёт трафика.** Трафик всегда хранится как дельты, не как накопленные значения. Короткие сессии учитываются по эвристике «только что подключилась» (возраст < 2 × `UPDATE_INTERVAL`). Сбросы счётчиков OpenVPN и переподключения клиента на тот же `ip:port` детектируются автоматически.

### Обновление версии

Миграции схемы применяются автоматически при старте через `DatabaseManager._migrate`. Достаточно обновить образ и перезапустить — ручные шаги не нужны.

Ежедневный cleanup сам удаляет orphaned `user_stats`, пересчитывает агрегаты по мере истечения сессий по retention и примерно раз в неделю делает `VACUUM` — долгоживущие инсталляции не требуют ручного обслуживания.

## Makefile

```bash
make up         # Запуск
make down       # Остановка
make restart    # Перезапуск
make logs       # Просмотр логов
make tail-logs  # Последние 100 строк лога с follow
make clean      # Удалить контейнеры и стереть data/
make shell      # Шелл внутри контейнера
```

## SSL (опционально)

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/nginx.key -out nginx/ssl/nginx.crt
```

## Лицензия

MIT
