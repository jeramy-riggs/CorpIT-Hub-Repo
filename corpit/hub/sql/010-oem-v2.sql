-- 010-oem-v2.sql — OEM v2 (push-button Okta -> Entra migration) tables. DESIGN.md section 1.
-- Additive only: CREATE TABLE IF NOT EXISTS, nothing existing is altered, dropped or renamed.
-- Row immutability (enforced in oem-v2-store.js): a finished oem_verification_attempt and a live/superseded
-- oem_config_revision are never UPDATEd except superseded_by/superseded_at.
-- Hard rule 2: no column here ever holds a secret; the store refuses a config carrying a secret-looking key.

-- One row per collector run (global: scope NULL; per-app: scope = Okta app id). A failed run never touches the
-- previous success row, so "last attempt" and "last success" are two different facts (bug 11).
CREATE TABLE IF NOT EXISTS oem_source_generation (
  id            INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  source_key    VARCHAR(64) NOT NULL,
  scope         VARCHAR(64) NULL,
  job_id        INT NULL,
  status        ENUM('running','success','failed','partial') NOT NULL DEFAULT 'running',
  started_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at   DATETIME NULL,
  records       INT NULL,
  error         VARCHAR(500) NULL,
  actor_email   VARCHAR(190) NULL,
  KEY k1 (source_key, scope, status, finished_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- An Entra service principal that a decision pointed at and that is no longer in Entra (bug 1). The last mirror
-- row is kept as `snapshot`; `reappeared_at` is stamped if the same object id is ever seen again (a recreated
-- app with the same display name gets a NEW object id and is never rebound automatically).
CREATE TABLE IF NOT EXISTS oem_entra_tombstone (
  entra_id      CHAR(36) NOT NULL PRIMARY KEY,
  app_id        CHAR(36) NULL,
  display_name  VARCHAR(255) NULL,
  last_seen_at  DATETIME NULL,
  detected_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  detected_by   VARCHAR(64) NULL,
  snapshot      JSON NULL,
  reappeared_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Match lifecycle per (Okta app, Entra service principal OBJECT id). The legacy app_matches table stays the
-- write-through record other pages read; this table carries the v2 states (invalidated, superseded) and history.
CREATE TABLE IF NOT EXISTS oem_app_match (
  id                 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  okta_app_id        VARCHAR(32) NOT NULL,
  entra_sp_id        CHAR(36) NOT NULL,
  entra_display_name VARCHAR(255) NULL,
  state              ENUM('suggested','shortlisted','confirmed','rejected','invalidated','superseded') NOT NULL,
  score              DECIMAL(4,3) NULL,
  method             VARCHAR(64) NULL,
  evidence           JSON NULL,
  reason             VARCHAR(500) NULL,
  legacy_row_id      INT NULL,
  created_by         VARCHAR(190) NULL,
  created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  invalidated_at     DATETIME NULL,
  invalidated_reason VARCHAR(255) NULL,
  superseded_by      INT NULL,
  KEY k1 (okta_app_id, state),
  KEY k2 (entra_sp_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Configuration revisions. Editable while draft; plan approval binds to plan_hash; a live revision is the immutable
-- evidence baseline and any later edit forks a new draft (revision_no + 1). `version` is the optimistic-concurrency
-- counter for draft edits.
CREATE TABLE IF NOT EXISTS oem_config_revision (
  id                      INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  okta_app_id             VARCHAR(32) NOT NULL,
  revision_no             INT NOT NULL DEFAULT 1,
  match_id                INT NULL,
  entra_sp_id             CHAR(36) NULL,
  protocol                VARCHAR(24) NOT NULL,
  state                   ENUM('draft','plan_approved','entra_configured','awaiting_vendor','awaiting_verification','awaiting_live_approval','live','superseded') NOT NULL DEFAULT 'draft',
  config                  JSON NULL,
  plan                    JSON NULL,
  plan_hash               CHAR(64) NULL,
  plan_approved_by        VARCHAR(190) NULL,
  plan_approved_at        DATETIME NULL,
  plan_approved_hash      CHAR(64) NULL,
  migration_id            INT NULL,
  entra_configured_at     DATETIME NULL,
  vendor_template_key     VARCHAR(64) NULL,
  vendor_template_version VARCHAR(16) NULL,
  vendor_ready_by         VARCHAR(190) NULL,
  vendor_ready_at         DATETIME NULL,
  vendor_ready_note       VARCHAR(500) NULL,
  owner_confirmed_by      VARCHAR(190) NULL,
  owner_confirmed_at      DATETIME NULL,
  owner_confirmed_note    VARCHAR(500) NULL,
  live_by                 VARCHAR(190) NULL,
  live_at                 DATETIME NULL,
  superseded_by           INT NULL,
  superseded_at           DATETIME NULL,
  version                 INT NOT NULL DEFAULT 1,
  created_by              VARCHAR(190) NULL,
  created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY k1 (okta_app_id, state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One verification run = one attempt with child checks (polling never becomes a timeline row). Immutable once
-- finished; a new test creates a new attempt. plan_hash records the approved plan the evidence was generated against.
CREATE TABLE IF NOT EXISTS oem_verification_attempt (
  id           INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  revision_id  INT NOT NULL,
  okta_app_id  VARCHAR(32) NOT NULL,
  started_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at  DATETIME NULL,
  status       ENUM('running','pass','fail','inconclusive') NOT NULL DEFAULT 'running',
  checks       JSON NULL,
  summary      JSON NULL,
  actor_email  VARCHAR(190) NULL,
  plan_hash    CHAR(64) NULL,
  KEY k1 (revision_id),
  KEY k2 (okta_app_id, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- A privileged Live override: who, why, and exactly which predicates were not met. Never counted as verification.
CREATE TABLE IF NOT EXISTS oem_live_override (
  id                INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  revision_id       INT NOT NULL,
  okta_app_id       VARCHAR(32) NOT NULL,
  actor_email       VARCHAR(190) NOT NULL,
  reason            VARCHAR(1000) NOT NULL,
  failed_predicates JSON NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY k1 (revision_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
