-- Скрипт очистки дубликатов активных сессий
-- Script to clean duplicate active sessions

-- 1. Найти и показать дубликаты (для проверки)
-- Find and show duplicates (for verification)
SELECT 
    username, 
    server_name, 
    connected_since, 
    COUNT(*) as count
FROM sessions
WHERE disconnected_at IS NULL
GROUP BY username, server_name, connected_since
HAVING COUNT(*) > 1;

-- 2. Удалить дубликаты, оставив только запись с наименьшим ID
-- Delete duplicates, keeping only the record with the smallest ID
DELETE FROM sessions
WHERE id NOT IN (
    SELECT MIN(id)
    FROM sessions
    WHERE disconnected_at IS NULL
    GROUP BY username, server_name, connected_since
)
AND disconnected_at IS NULL;

-- 3. Проверить результат - должно быть 0 дубликатов
-- Verify result - should be 0 duplicates
SELECT 
    username, 
    server_name, 
    connected_since, 
    COUNT(*) as count
FROM sessions
WHERE disconnected_at IS NULL
GROUP BY username, server_name, connected_since
HAVING COUNT(*) > 1;

-- 4. Показать все активные сессии
-- Show all active sessions
SELECT 
    id,
    username,
    server_name,
    real_address,
    connected_since,
    bytes_received,
    bytes_sent
FROM sessions
WHERE disconnected_at IS NULL
ORDER BY server_name, username, connected_since;

