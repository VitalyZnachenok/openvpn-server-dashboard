# OpenVPN Server Dashboard

[English](README.md) | **Русский**

Мониторинг нескольких OpenVPN серверов с веб-интерфейсом.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)

## Возможности

- Поддержка нескольких серверов
- Графики трафика (5мин-7дней)
- Активные сессии в реальном времени
- Статистика пользователей с поиском/сортировкой
- Экспорт CSV/JSON
- Множественные сессии одного пользователя
- Автоочистка

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
  - SERVERS_CONFIG=server1:/path/status.log:/path/vpn.log;server2:/path/status.log
```

**Один сервер:**
```yaml
environment:
  - OPENVPN_STATUS_FILE=/var/log/openvpn/openvpn-status.log
```

### Конфиг OpenVPN
```
status /var/log/openvpn/openvpn-status.log
status-version 2
```

## Переменные окружения

| Переменная | По умолчанию | Описание |
|-----------|--------------|----------|
| `UPDATE_INTERVAL` | 60 | Интервал обновления (сек) |
| `RETENTION_DAYS` | 90 | Хранение сессий (дни) |
| `TRAFFIC_HISTORY_RETENTION_DAYS` | 30 | Хранение графиков (дни) |

## API

- `GET /api/health` - Проверка состояния
- `GET /api/servers` - Список серверов
- `GET /api/summary` - Сводка
- `GET /api/active_sessions?server=NAME` - Активные сессии
- `GET /api/user_stats?server=NAME&limit=50&search=user` - Статистика
- `GET /api/traffic_chart?server=NAME&hours=24` - Данные графиков
- `GET /api/export/sessions?format=csv` - Экспорт сессий
- `GET /api/export/users?format=json` - Экспорт пользователей

## База данных

SQLite с 3 таблицами:
- `sessions` - VPN сессии
- `user_stats` - Агрегированная статистика
- `traffic_history` - Дельты трафика для графиков

**Важно:** Трафик хранится как дельты, а не накопленные значения. Корректно обрабатывает переподключения.

## Makefile

```bash
make up        # Запуск
make down      # Остановка
make restart   # Перезапуск
make logs      # Просмотр логов
make clean     # Очистка всех данных
```

## SSL (опционально)

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/nginx.key -out nginx/ssl/nginx.crt
```

## Лицензия

MIT
