-- Retention Labels scan storage. Additive, idempotent; no scan or tenant changes.
-- Apply to corpit_hub on DEV itam. Field sizes match sp-label-scan-job.js.
CREATE TABLE IF NOT EXISTS sp_label_scan_runs (
  batch_id BIGINT UNSIGNED NOT NULL,
  started_at DATETIME NOT NULL,
  finished_at DATETIME NULL,
  status ENUM('running','done','failed') NOT NULL,
  labels_found INT UNSIGNED NOT NULL DEFAULT 0,
  items_found BIGINT UNSIGNED NOT NULL DEFAULT 0,
  truncated TINYINT UNSIGNED NOT NULL DEFAULT 0,
  error VARCHAR(1000) NULL,
  PRIMARY KEY (batch_id),
  KEY status_batch (status,batch_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sp_label_scan_labels (
  batch_id BIGINT UNSIGNED NOT NULL,
  label VARCHAR(255) NOT NULL,
  search_total BIGINT UNSIGNED NOT NULL DEFAULT 0,
  items_stored BIGINT UNSIGNED NOT NULL DEFAULT 0,
  truncated TINYINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (batch_id,label)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sp_label_scan_items (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  batch_id BIGINT UNSIGNED NOT NULL,
  label VARCHAR(255) NOT NULL,
  site_title VARCHAR(255) NULL,
  site_url VARCHAR(512) NULL,
  site_id VARCHAR(64) NULL,
  web_url VARCHAR(512) NULL,
  hub_id VARCHAR(64) NULL,
  hub_title VARCHAR(255) NULL,
  hub_url VARCHAR(512) NULL,
  library VARCHAR(255) NULL,
  library_url VARCHAR(1024) NULL,
  folder_path VARCHAR(1024) NULL,
  path VARCHAR(1024) NULL,
  file_name VARCHAR(512) NULL,
  file_ext VARCHAR(32) NULL,
  is_document TINYINT UNSIGNED NULL,
  size_bytes BIGINT UNSIGNED NULL,
  modified_at DATETIME NULL,
  modified_by VARCHAR(255) NULL,
  item_kind ENUM('file','folder','list_item') NULL,
  PRIMARY KEY (id),
  KEY batch_label (batch_id,label),
  KEY batch_site (batch_id,site_url(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
