-- detection_queries.sql
--
-- Demonstrates the same log-detection logic implemented in detect.py, but
-- using SQL. Assumes the log has been loaded into a table `auth_events`
-- with the schema below (see load_log_to_sqlite.py for how to populate it).
--
-- Schema:
--   auth_events(id INTEGER, event_time TEXT, status TEXT, user TEXT, ip TEXT)
--   event_time format: 'YYYY-MM-DD HH:MM:SS'

-- ============================================================
-- 1. Brute-force detection: IPs with >= 10 failed logins
--    within any 5-minute window
-- ============================================================
-- SQLite doesn't have a native "sliding window" clause, so we approximate
-- by counting failed attempts per IP within 5-minute buckets.
SELECT
    ip,
    strftime('%Y-%m-%d %H:', event_time) ||
        printf('%02d', (CAST(strftime('%M', event_time) AS INTEGER) / 5) * 5) AS time_bucket,
    COUNT(*) AS failed_attempts
FROM auth_events
WHERE status = 'Failed'
GROUP BY ip, time_bucket
HAVING failed_attempts >= 10
ORDER BY failed_attempts DESC;

-- ============================================================
-- 2. Off-hours successful logins (outside 07:00-21:00)
-- ============================================================
SELECT
    id,
    event_time,
    user,
    ip
FROM auth_events
WHERE status = 'Accepted'
  AND (CAST(strftime('%H', event_time) AS INTEGER) < 7
       OR CAST(strftime('%H', event_time) AS INTEGER) >= 21)
ORDER BY event_time;

-- ============================================================
-- 3. Successful login shortly after multiple failures from the same IP
--    (possible compromise / credential guessed correctly)
-- ============================================================
SELECT
    success.id,
    success.event_time AS success_time,
    success.user,
    success.ip,
    COUNT(fail.id) AS recent_failed_attempts
FROM auth_events AS success
JOIN auth_events AS fail
    ON fail.ip = success.ip
    AND fail.status = 'Failed'
    AND fail.event_time < success.event_time
    AND (strftime('%s', success.event_time) - strftime('%s', fail.event_time)) <= 300  -- 5 minutes
WHERE success.status = 'Accepted'
GROUP BY success.id
HAVING recent_failed_attempts >= 3
ORDER BY success.event_time;

-- ============================================================
-- 4. Quick summary: failed vs successful logins per IP
--    (useful as a first triage view)
-- ============================================================
SELECT
    ip,
    SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed_count,
    SUM(CASE WHEN status = 'Accepted' THEN 1 ELSE 0 END) AS success_count
FROM auth_events
GROUP BY ip
ORDER BY failed_count DESC;
