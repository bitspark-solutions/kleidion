-- 000005 down: drop the session metadata columns.

ALTER TABLE sessions
    DROP COLUMN user_agent,
    DROP COLUMN last_used_at;
