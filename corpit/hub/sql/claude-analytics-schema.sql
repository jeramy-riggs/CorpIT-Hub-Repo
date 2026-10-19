-- Claude Enterprise Analytics — local store for corpit.
-- Money is kept in CENTS exactly as the API returns it (decimal strings, fractional
-- cents are real: "1698.211075"). DECIMAL(18,6) preserves that; convert to dollars
-- at the API layer, never with a float in the collector.
-- Every table is upserted over a rolling window: Enterprise cost figures are revised
-- for up to 30 days, so a day's row is provisional until it ages out. Never insert-once.

CREATE TABLE IF NOT EXISTS claude_cost_daily (
  day               DATE          NOT NULL,
  product           VARCHAR(32)   NOT NULL DEFAULT '',   -- '' when the slice is not grouped
  model             VARCHAR(64)   NOT NULL DEFAULT '',
  amount_cents      DECIMAL(18,6) NOT NULL DEFAULT 0,    -- post-discount, pre-credit
  list_amount_cents DECIMAL(18,6) NOT NULL DEFAULT 0,    -- pre-discount
  requests          INT           NOT NULL DEFAULT 0,
  updated_at        TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (day, product, model),
  KEY idx_ccd_day (day),
  KEY idx_ccd_product (product)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS claude_usage_daily (
  day                 DATE        NOT NULL,
  model               VARCHAR(64) NOT NULL DEFAULT '',
  uncached_input      BIGINT      NOT NULL DEFAULT 0,
  cache_read          BIGINT      NOT NULL DEFAULT 0,
  cache_creation_5m   BIGINT      NOT NULL DEFAULT 0,
  cache_creation_1h   BIGINT      NOT NULL DEFAULT 0,
  output_tokens       BIGINT      NOT NULL DEFAULT 0,
  web_search_requests INT         NOT NULL DEFAULT 0,
  requests            INT         NOT NULL DEFAULT 0,
  updated_at          TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (day, model),
  KEY idx_cud_day (day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS claude_user_cost_daily (
  day          DATE          NOT NULL,
  user_id      VARCHAR(64)   NOT NULL,
  product      VARCHAR(32)   NOT NULL DEFAULT '',
  email        VARCHAR(255)  DEFAULT NULL,
  display_name VARCHAR(255)  DEFAULT NULL,
  amount_cents DECIMAL(18,6) NOT NULL DEFAULT 0,
  requests     INT           NOT NULL DEFAULT 0,
  deleted      TINYINT(1)    NOT NULL DEFAULT 0,
  updated_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (day, user_id, product),
  KEY idx_cucd_email (email),
  KEY idx_cucd_day (day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS claude_user_activity_daily (
  day                DATE         NOT NULL,
  user_id            VARCHAR(64)  NOT NULL,
  email              VARCHAR(255) DEFAULT NULL,
  chat_conversations INT NOT NULL DEFAULT 0,
  chat_messages      INT NOT NULL DEFAULT 0,
  chat_projects_used INT NOT NULL DEFAULT 0,
  chat_artifacts     INT NOT NULL DEFAULT 0,
  chat_skills_used   INT NOT NULL DEFAULT 0,
  cc_sessions        INT NOT NULL DEFAULT 0,
  cc_commits         INT NOT NULL DEFAULT 0,
  cc_prs             INT NOT NULL DEFAULT 0,
  cc_loc_added       INT NOT NULL DEFAULT 0,
  cc_loc_removed     INT NOT NULL DEFAULT 0,
  cc_edits_accepted  INT NOT NULL DEFAULT 0,
  cc_edits_rejected  INT NOT NULL DEFAULT 0,
  cowork_sessions    INT NOT NULL DEFAULT 0,
  cowork_actions     INT NOT NULL DEFAULT 0,
  cowork_file_edits  INT NOT NULL DEFAULT 0,
  cowork_messages    INT NOT NULL DEFAULT 0,
  office_sessions    INT NOT NULL DEFAULT 0,
  design_sessions    INT NOT NULL DEFAULT 0,
  science_sessions   INT NOT NULL DEFAULT 0,
  web_search_count   INT NOT NULL DEFAULT 0,
  last_activity_date DATE DEFAULT NULL,
  updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (day, user_id),
  KEY idx_cuad_email (email),
  KEY idx_cuad_day (day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS claude_summary_daily (
  day                    DATE NOT NULL PRIMARY KEY,
  dau                    INT NOT NULL DEFAULT 0,
  wau                    INT NOT NULL DEFAULT 0,
  mau                    INT NOT NULL DEFAULT 0,
  chat_dau INT NOT NULL DEFAULT 0, chat_wau INT NOT NULL DEFAULT 0, chat_mau INT NOT NULL DEFAULT 0,
  cc_dau   INT NOT NULL DEFAULT 0, cc_wau   INT NOT NULL DEFAULT 0, cc_mau   INT NOT NULL DEFAULT 0,
  cowork_dau INT NOT NULL DEFAULT 0, cowork_wau INT NOT NULL DEFAULT 0, cowork_mau INT NOT NULL DEFAULT 0,
  design_mau INT NOT NULL DEFAULT 0,
  office_mau INT NOT NULL DEFAULT 0,
  assigned_seats         INT NOT NULL DEFAULT 0,
  pending_invites        INT NOT NULL DEFAULT 0,
  daily_adoption_rate    DECIMAL(6,2) DEFAULT NULL,
  weekly_adoption_rate   DECIMAL(6,2) DEFAULT NULL,
  monthly_adoption_rate  DECIMAL(6,2) DEFAULT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Every ITAM collector needs a run log; without one a silent failure looks like
-- "no spend today" rather than "the sync died".
CREATE TABLE IF NOT EXISTS claude_sync_log (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  ran_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  endpoint          VARCHAR(48) NOT NULL,
  window_start      DATE DEFAULT NULL,
  window_end        DATE DEFAULT NULL,
  api_calls         INT NOT NULL DEFAULT 0,
  rows_upserted     INT NOT NULL DEFAULT 0,
  status            ENUM('ok','error','partial','no-scope') NOT NULL DEFAULT 'ok',
  error             TEXT DEFAULT NULL,
  duration_ms       INT NOT NULL DEFAULT 0,
  data_refreshed_at DATETIME DEFAULT NULL,
  KEY idx_csl_ran (ran_at),
  KEY idx_csl_endpoint (endpoint)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================================
-- Admin-scoped data (2026-09-01). Filled by collector steps 6-8, which need a key
-- carrying read:spend_limits / read:members. With the read:analytics-only key the
-- steps log 'no-scope' and these stay EMPTY, which is exactly how the routes detect
-- "not live" and keep the CSV fallback. Money = cents, DECIMAL(18,6), same as above.
-- ============================================================================

-- Effective spend limit per (member, period) — CURRENT STATE, replaced on every full pull.
CREATE TABLE IF NOT EXISTS claude_spend_limit (
  user_id         VARCHAR(64)   NOT NULL,
  period          VARCHAR(16)   NOT NULL DEFAULT 'monthly',
  email           VARCHAR(255)  DEFAULT NULL,
  display_name    VARCHAR(255)  DEFAULT NULL,
  deleted         TINYINT(1)    NOT NULL DEFAULT 0,
  amount_cents    DECIMAL(18,6) DEFAULT NULL,           -- NULL = no limit for this period (unlimited)
  currency        CHAR(3)       NOT NULL DEFAULT 'USD',
  source_type     VARCHAR(32)   NOT NULL DEFAULT '',    -- user | seat_tier | rbac_group | organization | organization_service | <future>
  source_ref      VARCHAR(128)  DEFAULT NULL,           -- seat tier name / rbac_group_id / service / user_id
  spend_limit_id  VARCHAR(64)   DEFAULT NULL,
  ptd_spend_cents DECIMAL(18,6) NOT NULL DEFAULT 0,     -- period_to_date_spend ("0" when temporarily unavailable)
  fetched_at      DATETIME      NOT NULL,
  PRIMARY KEY (user_id, period),
  KEY idx_csl_email (email),
  KEY idx_csl_fetched (fetched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per member/period/day so limit changes stay visible over time.
CREATE TABLE IF NOT EXISTS claude_spend_limit_daily (
  day             DATE          NOT NULL,
  user_id         VARCHAR(64)   NOT NULL,
  period          VARCHAR(16)   NOT NULL DEFAULT 'monthly',
  email           VARCHAR(255)  DEFAULT NULL,
  amount_cents    DECIMAL(18,6) DEFAULT NULL,
  source_type     VARCHAR(32)   NOT NULL DEFAULT '',
  ptd_spend_cents DECIMAL(18,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (day, user_id, period)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Spend-limit increase requests (history kept; the API drops ex-members' requests).
CREATE TABLE IF NOT EXISTS claude_limit_request (
  id                  VARCHAR(64)   NOT NULL,
  user_id             VARCHAR(64)   DEFAULT NULL,
  email               VARCHAR(255)  DEFAULT NULL,
  display_name        VARCHAR(255)  DEFAULT NULL,
  status              VARCHAR(16)   NOT NULL DEFAULT 'pending',   -- pending | approved | denied
  period              VARCHAR(16)   NOT NULL DEFAULT 'monthly',
  created_at          DATETIME      DEFAULT NULL,
  resolved_at         DATETIME      DEFAULT NULL,
  resolved_by         VARCHAR(255)  DEFAULT NULL,                 -- email/name, or api-key:<id>
  current_limit_cents DECIMAL(18,6) DEFAULT NULL,                 -- from spend_summary (pending only)
  current_source_type VARCHAR(32)   DEFAULT NULL,
  ptd_spend_cents     DECIMAL(18,6) DEFAULT NULL,
  fetched_at          DATETIME      NOT NULL,
  PRIMARY KEY (id),
  KEY idx_clr_status (status),
  KEY idx_clr_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Provisioned roster (GET /v1/organizations/users) — CURRENT STATE, replaced on every full pull.
CREATE TABLE IF NOT EXISTS claude_member (
  user_id      VARCHAR(64)  NOT NULL,
  email        VARCHAR(255) DEFAULT NULL,
  display_name VARCHAR(255) DEFAULT NULL,
  role         VARCHAR(32)  DEFAULT NULL,     -- user | managed | owner | membership_admin | primary_owner
  added_at     DATETIME     DEFAULT NULL,
  fetched_at   DATETIME     NOT NULL,
  PRIMARY KEY (user_id),
  KEY idx_cm_email (email),
  KEY idx_cm_fetched (fetched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- claude_sync_log.status gains 'no-scope' (a key without the scope is a state, not an error).
-- Appending an ENUM member is an instant metadata change in MySQL 8, and re-running MODIFY with
-- an identical definition is a no-op, so this statement is safe on every deploy. It MUST run
-- before the new collector is installed.
ALTER TABLE claude_sync_log MODIFY status ENUM('ok','error','partial','no-scope') NOT NULL DEFAULT 'ok';
-- Claude token detail (2026-09-02). Adds the two token slices the Analytics API
-- serves on the read:analytics key but that we were not storing: per-member tokens
-- and org tokens by product. Same rules as the rest of the store: rolling window,
-- always UPSERT (Anthropic revises figures for up to 30 days), counts are BIGINT.

-- Per-member tokens per day (GET /analytics/user_usage_report, no group_by so one
-- row per member per day). total_tokens is returned by the API; it is stored as
-- given rather than re-derived, because the API's definition is the billable one.
CREATE TABLE IF NOT EXISTS claude_user_usage_daily (
  day                 DATE          NOT NULL,
  user_id             VARCHAR(64)   NOT NULL,
  email               VARCHAR(255)  DEFAULT NULL,
  display_name        VARCHAR(255)  DEFAULT NULL,
  uncached_input      BIGINT        NOT NULL DEFAULT 0,
  cache_read          BIGINT        NOT NULL DEFAULT 0,
  cache_creation_5m   BIGINT        NOT NULL DEFAULT 0,
  cache_creation_1h   BIGINT        NOT NULL DEFAULT 0,
  output_tokens       BIGINT        NOT NULL DEFAULT 0,
  total_tokens        BIGINT        NOT NULL DEFAULT 0,
  web_search_requests INT           NOT NULL DEFAULT 0,
  requests            INT           NOT NULL DEFAULT 0,
  deleted             TINYINT(1)    NOT NULL DEFAULT 0,
  updated_at          TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (day, user_id),
  KEY idx_cuud_email (email),
  KEY idx_cuud_day (day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Org tokens by product per day (GET /analytics/usage_report&group_by[]=product).
-- Kept in its own table rather than widening claude_usage_daily's primary key, so the
-- existing by-model rows and every query over them stay exactly as they are.
CREATE TABLE IF NOT EXISTS claude_usage_product_daily (
  day                 DATE          NOT NULL,
  product             VARCHAR(32)   NOT NULL DEFAULT '',
  uncached_input      BIGINT        NOT NULL DEFAULT 0,
  cache_read          BIGINT        NOT NULL DEFAULT 0,
  cache_creation_5m   BIGINT        NOT NULL DEFAULT 0,
  cache_creation_1h   BIGINT        NOT NULL DEFAULT 0,
  output_tokens       BIGINT        NOT NULL DEFAULT 0,
  web_search_requests INT           NOT NULL DEFAULT 0,
  requests            INT           NOT NULL DEFAULT 0,
  updated_at          TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (day, product),
  KEY idx_cupd_day (day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
