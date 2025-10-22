# OpenVPN Server Dashboard

[English](README.md) | **Русский**

Многосерверная система мониторинга и визуализации статистики OpenVPN с веб-интерфейсом.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)

## 📋 Возможности

- 🖥️ **Мультисерверная поддержка** - Мониторинг нескольких OpenVPN серверов одновременно
- 📊 **Визуализация трафика** - Интерактивные графики входящего и исходящего трафика
- 👥 **Мониторинг активных подключений** - Отслеживание текущих пользователей в реальном времени
- 📈 **Статистика пользователей** - Подробная информация по каждому пользователю
- 💾 **База данных SQLite** - Хранение истории сессий и трафика
- 🔄 **Автоматическое обновление** - Обновление данных каждую минуту (настраивается)
- 📥 **Экспорт данных** - Экспорт статистики в CSV и JSON форматы
- 🐳 **Docker контейнеризация** - Простое развертывание с Docker Compose
- 🔒 **Nginx с SSL** - Готовая конфигурация reverse proxy с поддержкой HTTPS
- 🧹 **Автоматическая очистка** - Удаление старых данных согласно политике хранения

## 📸 Интерфейс

Dashboard предоставляет:
- Сводную информацию (активные пользователи, всего пользователей, сессии за сегодня, общий трафик)
- Графики трафика за разные периоды (5 мин, 30 мин, 1 час, 6 часов, 24 часа, неделя)
- Таблицу активных сессий с данными о подключении
- Статистику пользователей с фильтрацией и поиском

## 🚀 Быстрый старт

### Предварительные требования

- Docker и Docker Compose
- OpenVPN сервер с включенным status-файлом
- (Опционально) Nginx для HTTPS и базовой аутентификации

### Установка

1. **Клонируйте репозиторий:**
```bash
git clone https://github.com/yourusername/openvpn-server-dashboard.git
cd openvpn-server-dashboard
```

2. **Настройте конфигурацию OpenVPN серверов:**

Отредактируйте `docker-compose.yml` и укажите ваши серверы в переменной `SERVERS_CONFIG`:

```yaml
environment:
  - SERVERS_CONFIG=
      server1:/var/log/openvpn/server1-status.log:/var/log/openvpn/server1.log;
      server2:/var/log/openvpn/server2-status.log:/var/log/openvpn/server2.log
```

Формат: `SERVER_NAME:STATUS_FILE:LOG_FILE`

**Для одного сервера:**
```yaml
environment:
  - OPENVPN_STATUS_FILE=/var/log/openvpn/openvpn-status.log
  - OPENVPN_LOG_FILE=/var/log/openvpn/openvpn.log
```

3. **Создайте директорию для данных:**
```bash
mkdir -p data
```

4. **Запустите с помощью Docker Compose:**
```bash
make up
# или
docker compose up -d
```

5. **Откройте в браузере:**
```
http://localhost:80
```

## ⚙️ Конфигурация

### Переменные окружения

| Переменная | Описание | Значение по умолчанию |
|-----------|----------|----------------------|
| `SERVERS_CONFIG` | Конфигурация нескольких серверов (формат: NAME:STATUS:LOG) | - |
| `OPENVPN_STATUS_FILE` | Путь к status-файлу OpenVPN (для одного сервера) | `/var/log/openvpn/openvpn-status.log` |
| `OPENVPN_LOG_FILE` | Путь к лог-файлу OpenVPN (для одного сервера) | `/var/log/openvpn/openvpn.log` |
| `DB_PATH` | Путь к базе данных SQLite | `/app/data/openvpn_stats.db` |
| `UPDATE_INTERVAL` | Интервал обновления данных (в секундах) | `60` |
| `RETENTION_DAYS` | Срок хранения сессий (в днях) | `90` |
| `TRAFFIC_HISTORY_RETENTION_DAYS` | Срок хранения истории трафика (в днях) | `30` |
| `DEFAULT_LIMIT` | Лимит записей по умолчанию | `50` |
| `MAX_LIMIT` | Максимальный лимит записей | `500` |
| `FLASK_PORT` | Порт Flask приложения | `5000` |
| `FLASK_HOST` | Хост Flask приложения | `0.0.0.0` |

### Конфигурация OpenVPN

Для работы dashboard'а OpenVPN должен записывать status-файл. Добавьте в конфигурацию вашего OpenVPN сервера:

```bash
status /var/log/openvpn/openvpn-status.log
status-version 2
```

### Nginx и SSL

1. **Создайте SSL сертификат:**
```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/nginx.key -out nginx/ssl/nginx.crt
```

2. **Настройте базовую аутентификацию (опционально):**
```bash
# Установите apache2-utils
apt-get install apache2-utils

# Создайте файл с паролями
htpasswd -c nginx/.htpasswd admin
```

3. **Отредактируйте `nginx/sites-enabled/vpn-stats.conf`** под ваш домен

## 🛠️ Makefile команды

Проект включает Makefile для удобного управления:

```bash
make help      # Показать справку
make build     # Собрать Docker образы
make up        # Запустить сервисы
make down      # Остановить сервисы
make restart   # Перезапустить сервисы
make logs      # Просмотр логов
make clean     # Очистить данные и остановить контейнеры
make shell     # Войти в контейнер
make tail-logs # Просмотр последних 100 строк логов
```

## 📡 API Endpoints

Dashboard предоставляет REST API для интеграции:

### Общие
- `GET /api/health` - Проверка состояния сервиса
- `GET /api/servers` - Список настроенных серверов
- `GET /api/summary` - Сводная статистика

### Сессии
- `GET /api/active_sessions?server=SERVER_NAME` - Активные сессии
- `GET /api/export/sessions?format=csv&server=SERVER_NAME` - Экспорт активных сессий

### Статистика пользователей
- `GET /api/user_stats?server=SERVER_NAME&limit=50&offset=0&search=username` - Статистика пользователей
- `GET /api/export/users?format=json&server=SERVER_NAME` - Экспорт статистики

### Графики
- `GET /api/traffic_chart?server=SERVER_NAME&hours=24` - Данные трафика для графиков

**Параметры:**
- `server` - (опционально) имя сервера для фильтрации
- `hours` - период для графиков (0.083 = 5 мин, 0.5 = 30 мин, 1, 6, 24, 168 = неделя)
- `format` - формат экспорта (csv или json)
- `limit` - количество записей
- `offset` - смещение для пагинации
- `search` - поиск по имени пользователя

## 📊 Структура базы данных

### Таблица `sessions`
Хранит информацию о VPN сессиях:
- username, server_name, real_address, virtual_address
- bytes_received, bytes_sent
- connected_since, disconnected_at, session_duration

### Таблица `user_stats`
Агрегированная статистика пользователей:
- username, server_name
- total_sessions, total_time_seconds
- total_bytes_sent, total_bytes_received
- last_seen, current_status

### Таблица `traffic_history`
История трафика для построения графиков:
- server_name, username (опционально)
- bytes_in, bytes_out, active_users
- timestamp

## 🔧 Разработка

### Локальный запуск (без Docker)

1. **Установите зависимости:**
```bash
pip install -r requirements.txt
```

2. **Установите переменные окружения:**
```bash
export DB_PATH=./data/openvpn_stats.db
export OPENVPN_STATUS_FILE=/var/log/openvpn/openvpn-status.log
export UPDATE_INTERVAL=60
```

3. **Запустите приложение:**
```bash
python app.py
```

### Структура проекта

```
openvpn-server-dashboard/
├── app.py                      # Основное Flask приложение
├── requirements.txt            # Python зависимости
├── Dockerfile                  # Docker образ
├── docker-compose.yml          # Docker Compose конфигурация
├── Makefile                   # Команды управления
├── templates/
│   └── index.html             # HTML шаблон интерфейса
├── static/                    # Статические файлы (CSS, JS)
├── nginx/
│   ├── nginx.conf             # Конфигурация Nginx
│   ├── sites-enabled/
│   │   └── vpn-stats.conf    # Виртуальный хост
│   └── ssl/                   # SSL сертификаты
├── data/                      # База данных SQLite (создается автоматически)
└── LICENSE
```

## 🐛 Устранение неполадок

### Проблема: Status-файл не найден

Убедитесь, что:
1. OpenVPN настроен на создание status-файла
2. Путь к status-файлу в docker-compose.yml правильный
3. Volume смонтирован корректно

### Проблема: Нет данных в графиках

- Подождите несколько минут после запуска (данные собираются по расписанию)
- Проверьте, что активны подключения к VPN
- Проверьте логи: `make logs`

### Проблема: Ошибка подключения к базе данных

```bash
# Проверьте права доступа к директории data
chmod 755 data/

# Или пересоздайте контейнер
make clean
make up
```

## 📝 Лицензия

Этот проект распространяется под лицензией MIT. См. файл [LICENSE](LICENSE) для подробностей.

## 🤝 Вклад

Приветствуются Pull Request'ы! Для больших изменений пожалуйста сначала откройте Issue для обсуждения.

## 📧 Контакты

Если у вас есть вопросы или предложения, создайте Issue в репозитории.

## ⭐ Благодарности

- Flask и экосистема Python
- Chart.js для визуализации
- Сообщество OpenVPN

---

**Примечание:** Этот dashboard предназначен для OpenVPN версии 2.5+ со status-version 2.

