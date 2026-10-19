-- ---------------------------------------------------------------------------
-- observability-schema.sql - the four obs_* tables and the one column this
-- build adds to srv_job_run.                                       2026-09-07
--
-- Idempotent and additive: safe to re-run, and it alters nothing that existed
-- before this build except by adding a nullable column. Until this file was
-- written the DDL lived only in /tmp, so the tables the observability page
-- depends on could not be rebuilt from the deploy tree at all.
--
--   mysql corpit_hub < sql/observability-schema.sql
--
-- The job REGISTRY (obs_job) is seeded separately from obs-jobs.json by
-- obs-seed-jobs.js at API startup. This file creates the table; that file
-- fills it.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS `obs_client_event` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `occurred_at` datetime NOT NULL,
  `received_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `kind` enum('error','rejection','fetch_fail','resource_fail','degraded','slow') COLLATE utf8mb4_unicode_ci NOT NULL,
  `severity` enum('info','warn','error') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'error',
  `page` varchar(160) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `app_key` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `widget` varchar(96) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `message` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `detail` text COLLATE utf8mb4_unicode_ci,
  `source` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `line` int DEFAULT NULL,
  `col` int DEFAULT NULL,
  `target_url` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `http_status` smallint DEFAULT NULL,
  `duration_ms` int DEFAULT NULL,
  `actor_key` char(16) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `session_key` char(16) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `viewport` varchar(16) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ua_family` varchar(48) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `app_version` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `fingerprint` char(40) COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_oce_time` (`occurred_at`),
  KEY `ix_oce_fp_time` (`fingerprint`,`occurred_at`),
  KEY `ix_oce_page_time` (`page`,`occurred_at`),
  KEY `ix_oce_kind_time` (`kind`,`occurred_at`),
  KEY `ix_oce_widget` (`widget`,`occurred_at`)
) ENGINE=InnoDB AUTO_INCREMENT=92 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `obs_request` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `at` datetime NOT NULL,
  `app` varchar(24) COLLATE utf8mb4_unicode_ci NOT NULL,
  `method` varchar(8) COLLATE utf8mb4_unicode_ci NOT NULL,
  `route` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `status` smallint NOT NULL,
  `duration_ms` int NOT NULL,
  `bytes` int DEFAULT NULL,
  `actor_key` char(16) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `client_ip` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `err` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `sampled` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `ix_or_time` (`at`),
  KEY `ix_or_route_time` (`route`,`at`),
  KEY `ix_or_status_time` (`status`,`at`)
) ENGINE=InnoDB AUTO_INCREMENT=692 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `obs_dependency` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `at` datetime NOT NULL,
  `app` varchar(24) COLLATE utf8mb4_unicode_ci NOT NULL,
  `vendor` varchar(40) COLLATE utf8mb4_unicode_ci NOT NULL,
  `operation` varchar(120) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
  `method` varchar(8) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `host` varchar(120) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `path` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` smallint DEFAULT NULL,
  `ok` tinyint(1) NOT NULL DEFAULT '0',
  `duration_ms` int DEFAULT NULL,
  `err` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_od_time` (`at`),
  KEY `ix_od_vendor_time` (`vendor`,`at`),
  KEY `ix_od_vendor_ok` (`vendor`,`ok`,`at`)
) ENGINE=InnoDB AUTO_INCREMENT=1059 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `obs_job` (
  `job_name` varchar(191) COLLATE utf8mb4_unicode_ci NOT NULL,
  `label` varchar(160) COLLATE utf8mb4_unicode_ci NOT NULL,
  `script` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `owner_page` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cadence_min` int NOT NULL,
  `grace_min` int NOT NULL DEFAULT '30',
  `enabled` tinyint(1) NOT NULL DEFAULT '1',
  `scheduled` tinyint(1) NOT NULL DEFAULT '0',
  `schedule_src` varchar(191) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `notes` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`job_name`),
  KEY `ix_oj_page` (`owner_page`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ---------------------------------------------------------------------------
-- srv_job_run.host - which machine wrote this run row.
--
-- srv_job_run predates this build and had no such column, while corpit_hub was
-- seeded from ITAM: 956 of its rows describe jobs that ran on ITAM in August and
-- were indistinguishable from this host's own. Two DECLARED jobs were resolving
-- their "last run" against those rows. Unstamped, a seeded row with a recent
-- timestamp paints a job green on a host where it has never run once - which is
-- the Cert Watchtower failure exactly.
--
-- Rows written before the column existed stay NULL. NULL means "provenance not
-- recorded", and the resolver reports those separately rather than counting them
-- as evidence either way.
--
-- MySQL 8 has no ADD COLUMN IF NOT EXISTS, hence the prepared statement.
-- ---------------------------------------------------------------------------
SET @has_host := (SELECT COUNT(*) FROM information_schema.COLUMNS
                  WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'srv_job_run' AND COLUMN_NAME = 'host');
SET @ddl := IF(@has_host > 0, 'DO 0',
  'ALTER TABLE srv_job_run ADD COLUMN host varchar(64) DEFAULT NULL AFTER state');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
