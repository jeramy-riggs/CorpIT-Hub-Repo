-- 011-oem-v2-live-freeze.sql — authz-7: freeze WHAT went live on oem_config_revision.
--   live_attempt_id   the verification attempt the sign-off was judged against (never the latest one afterwards)
--   live_generations  {"okta": <oem_source_generation.id>, "entra": <oem_source_generation.id>} — the mirror
--                     generations current at sign-off, so the evidence package never drifts to a later mirror.
-- Idempotent on MySQL 8.0.46 (no ADD COLUMN IF NOT EXISTS): information_schema check + PREPARE/EXECUTE,
-- the same pattern as 005-oem-ui.sql. Safe to re-run.

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oem_config_revision' AND COLUMN_NAME = 'live_attempt_id');
SET @s := IF(@c = 0, 'ALTER TABLE oem_config_revision ADD COLUMN live_attempt_id BIGINT NULL AFTER live_at', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oem_config_revision' AND COLUMN_NAME = 'live_generations');
SET @s := IF(@c = 0, 'ALTER TABLE oem_config_revision ADD COLUMN live_generations JSON NULL AFTER live_attempt_id', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- honesty-9: owner_confirmed_note now holds the attestation object as JSON ({ownerEmail, testedUser, testedAt,
-- whatLoaded, claimsSeen, note}); 500 characters is too short for a real whatLoaded/claimsSeen. Widen to TEXT once.
SET @l := (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'oem_config_revision' AND COLUMN_NAME = 'owner_confirmed_note');
SET @s := IF(@l IS NOT NULL AND @l < 65535, 'ALTER TABLE oem_config_revision MODIFY COLUMN owner_confirmed_note TEXT NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
