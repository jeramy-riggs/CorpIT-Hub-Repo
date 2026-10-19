-- 012-oem-staged.sql — Entra gallery mirror + Entra export Staged/Complete with sign-in evidence (drop 8e).
-- Additive only: CREATE TABLE IF NOT EXISTS, nothing existing is altered, dropped or renamed. Safe to re-run.
-- Hard rule 2: no column here ever holds a secret; sign-in evidence keeps who/when/how, never an IP or a token.

-- The Entra application gallery (applicationTemplates) filtered to templates that carry an SSO mode
-- (saml / oidc / password). Read once by the entra-gallery job; `stem` is the normalised product name used
-- to find "the OpenID Connect template for this vendor" (oem-v2-model.js galleryStem).
CREATE TABLE IF NOT EXISTS oem_gallery_template (
  id            CHAR(36) NOT NULL PRIMARY KEY,
  display_name  VARCHAR(255) NOT NULL,
  publisher     VARCHAR(255) NULL,
  modes         VARCHAR(120) NOT NULL DEFAULT '',
  stem          VARCHAR(255) NOT NULL DEFAULT '',
  collected_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY k_stem (stem(64)),
  KEY k_name (display_name(64))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row per service principal in the Entra "export service principals" CSV Jeramy imports. `status` is the
-- only state: staged until a successful interactive Entra sign-in is seen (oem-staged.js checkStagedSignIns),
-- then complete — and complete is terminal. Counts are the last check's mirror numbers, never a decision.
CREATE TABLE IF NOT EXISTS oem_entra_export (
  entra_id             CHAR(36) NOT NULL PRIMARY KEY,
  app_id               CHAR(36) NULL,
  display_name         VARCHAR(255) NOT NULL,
  identifier_uri       VARCHAR(500) NULL,
  homepage             VARCHAR(500) NULL,
  export_state         VARCHAR(40) NULL,
  source_file          VARCHAR(255) NULL,
  imported_by          VARCHAR(190) NULL,
  imported_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status               ENUM('staged','complete') NOT NULL DEFAULT 'staged',
  staged_at            DATETIME NULL,
  completed_at         DATETIME NULL,
  completed_signin_id  VARCHAR(64) NULL,
  completed_signin_at  DATETIME NULL,
  completed_user       VARCHAR(190) NULL,
  last_checked_at      DATETIME NULL,
  signin_ok            INT NOT NULL DEFAULT 0,
  signin_fail          INT NOT NULL DEFAULT 0,
  signin_last_ok_at    DATETIME NULL,
  signin_users         INT NOT NULL DEFAULT 0,
  removed_at           DATETIME NULL,
  KEY k_app (app_id),
  KEY k_status (status, removed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The sign-in that completed an export row, plus later successes the check records (one row per Entra sign-in
-- id). Who / when / which client / CA result / where (country only) — never an IP address, never a token.
CREATE TABLE IF NOT EXISTS oem_signin_evidence (
  id                   BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  entra_id             CHAR(36) NOT NULL,
  app_id               CHAR(36) NULL,
  signin_id            VARCHAR(64) NOT NULL,
  signin_at            DATETIME NOT NULL,
  user_principal_name  VARCHAR(190) NULL,
  client_app           VARCHAR(120) NULL,
  ca_status            VARCHAR(40) NULL,
  auth_requirement     VARCHAR(40) NULL,
  interactive          TINYINT(1) NOT NULL DEFAULT 1,
  location_country     VARCHAR(8) NULL,
  source               ENUM('mirror','graph') NOT NULL DEFAULT 'mirror',
  recorded_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY u_signin (signin_id),
  KEY k_entra (entra_id, signin_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
