# Исправление дубликатов активных сессий
# Fix for Duplicate Active Sessions

## Проблема (Problem)

В предыдущей версии система неправильно отслеживала отключенные сессии:
- Использовался словарь `{username: session}`, который перезаписывал данные
- Если у пользователя было несколько активных сессий, старые "зависали"
- Это приводило к дубликатам в таблице активных сессий

In the previous version, the system incorrectly tracked disconnected sessions:
- Used a dictionary `{username: session}` that overwrote data
- If a user had multiple active sessions, old ones remained "hanging"
- This led to duplicates in the active sessions table

## Решение (Solution)

### 1. Исправлена логика отслеживания (Fixed tracking logic)

**Было (Was):**
```python
db_active_users = {s['username']: s for s in db_active_sessions}  # Dictionary overwrites!
```

**Стало (Now):**
```python
# Create set of current session keys (username + connected_since)
current_session_keys = set()
for session in sessions:
    key = (session.username, session.connected_since)
    current_session_keys.add(key)
```

Теперь проверяется **конкретная сессия** по паре (username, connected_since), а не только username.

Now checks **specific session** by tuple (username, connected_since), not just username.

### 2. Добавлен уникальный индекс (Added unique index)

```sql
CREATE UNIQUE INDEX idx_unique_active_session 
ON sessions(username, server_name, connected_since)
WHERE disconnected_at IS NULL
```

Это предотвращает создание дубликатов на уровне базы данных.

This prevents duplicate creation at the database level.

## Миграция (Migration)

### Шаг 1: Остановить контейнер (Stop container)
```bash
make down
# или
docker compose down
```

### Шаг 2: Сделать бэкап БД (Backup database)
```bash
cp data/openvpn_stats.db data/openvpn_stats.db.backup
```

### Шаг 3: Очистить дубликаты (Clean duplicates)

**Вариант A: Через SQLite CLI**
```bash
sqlite3 data/openvpn_stats.db < cleanup_duplicates.sql
```

**Вариант B: Вручную**
```bash
sqlite3 data/openvpn_stats.db
```

Затем выполните команды из `cleanup_duplicates.sql`:
```sql
-- Найти дубликаты
SELECT username, server_name, connected_since, COUNT(*) as count
FROM sessions
WHERE disconnected_at IS NULL
GROUP BY username, server_name, connected_since
HAVING COUNT(*) > 1;

-- Удалить дубликаты
DELETE FROM sessions
WHERE id NOT IN (
    SELECT MIN(id)
    FROM sessions
    WHERE disconnected_at IS NULL
    GROUP BY username, server_name, connected_since
)
AND disconnected_at IS NULL;
```

**Вариант C: Простое решение (если не критична история)**
```bash
sqlite3 data/openvpn_stats.db "DELETE FROM sessions WHERE disconnected_at IS NULL"
```
Это удалит все текущие активные сессии, они пересоздадутся при следующем обновлении.

### Шаг 4: Пересобрать и запустить (Rebuild and start)
```bash
make build
make up
```

Или:
```bash
docker compose build
docker compose up -d
```

### Шаг 5: Проверить логи (Check logs)
```bash
make logs
# или
docker compose logs -f openvpn-stats
```

Вы должны увидеть:
```
Database initialized at /app/data/openvpn_stats.db
Starting Multi-Server OpenVPN Statistics System
```

### Шаг 6: Проверить активные сессии (Check active sessions)

Откройте дашборд и проверьте, что:
- Нет дубликатов активных пользователей
- Каждая сессия отображается только один раз
- При переподключении старая сессия корректно закрывается

Open the dashboard and verify:
- No duplicate active users
- Each session displays only once
- Old sessions close correctly on reconnect

## Проверка работы (Testing)

### 1. Проверить уникальность (Check uniqueness)
```sql
SELECT username, server_name, connected_since, COUNT(*) as count
FROM sessions
WHERE disconnected_at IS NULL
GROUP BY username, server_name, connected_since
HAVING COUNT(*) > 1;
```

Должно вернуть 0 строк (Should return 0 rows).

### 2. Проверить индекс (Check index)
```sql
SELECT name FROM sqlite_master 
WHERE type='index' 
AND name='idx_unique_active_session';
```

Должен вернуть имя индекса (Should return index name).

### 3. Симулировать переподключение (Simulate reconnect)

1. Подключитесь к VPN
2. Проверьте активные сессии
3. Отключитесь и сразу переподключитесь
4. Проверьте что старая сессия закрылась (disconnected_at IS NOT NULL)
5. Проверьте что новая сессия появилась

## Возможные проблемы (Possible Issues)

### Ошибка: "UNIQUE constraint failed"

Это хорошо! Индекс работает и предотвращает дубликаты.
Если видите эту ошибку в логах - значит защита работает.

This is good! The index works and prevents duplicates.
If you see this error in logs - the protection is working.

### Много старых активных сессий

Если после миграции видите много старых активных сессий:

1. Остановите контейнер
2. Выполните:
```sql
DELETE FROM sessions WHERE disconnected_at IS NULL;
```
3. Запустите контейнер

Все текущие сессии пересоздадутся автоматически.

## Изменения в коде (Code Changes)

- **app.py, строки 667-697**: Исправлена логика отслеживания отключенных сессий
- **app.py, строки 140-146**: Добавлен уникальный индекс для активных сессий
- **cleanup_duplicates.sql**: SQL скрипт для очистки существующих дубликатов

---

**Дата изменения / Change Date:** 2025-10-27
**Версия / Version:** 1.2.0

