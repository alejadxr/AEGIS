-- close-test-incidents-2026-05-26.sql
-- Purpose: Mark 4 E2E test artifacts as resolved so the dashboard reflects reality.
-- These incidents were generated during the unified-feed plan execution (2026-05-26).
-- IPs belong to the 185.220.101.0/24 Tor exit range used for nikto/sqlmap probes
-- against own services. They are NOT real attackers.
-- Pi blocklist: .55/.99/.142 already removed. .42 blocked but also a test (sqlmap).
-- Author: AEGIS data-hygiene agent, 2026-05-26
-- DO NOT delete rows — keep for audit history.

BEGIN;

-- Safety pre-check: confirm exactly 4 matching rows
DO $$
DECLARE
    row_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO row_count
    FROM incidents
    WHERE source_ip IN (
        '185.220.101.142',
        '185.220.101.99',
        '185.220.101.55',
        '185.220.101.42'
    )
    AND detected_at >= '2026-05-26'::date
    AND status != 'resolved';

    IF row_count != 4 THEN
        RAISE EXCEPTION 'Expected 4 rows, found %. Rolling back.', row_count;
    END IF;
END $$;

UPDATE incidents
SET
    status      = 'resolved',
    resolved_at = NOW(),
    description = COALESCE(description || E'\n\n', '') ||
                  '[RESOLVED 2026-05-26] Synthetic test artifact from unified-feed E2E plan. '
                  'IPs are Tor exits (185.220.101.0/24) used for nikto/sqlmap probes against '
                  'own services during security plan execution. Not real attackers. '
                  'Pi blocklist cleaned (.55/.99/.142 removed; .42 still blocked as test artifact).'
WHERE source_ip IN (
    '185.220.101.142',
    '185.220.101.99',
    '185.220.101.55',
    '185.220.101.42'
)
AND detected_at >= '2026-05-26'::date
AND status != 'resolved';

COMMIT;
