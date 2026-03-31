CREATE DATABASE IF NOT EXISTS aegis_vpn
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE aegis_vpn;

CREATE TABLE IF NOT EXISTS event_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    service_name VARCHAR(64) NOT NULL,
    category VARCHAR(64) NOT NULL,
    event_name VARCHAR(128) NOT NULL,
    level VARCHAR(16) NOT NULL,
    ts_unix_ms VARCHAR(32) NOT NULL,
    fields_json JSON NOT NULL,
    prev_hmac CHAR(64) NULL,
    row_hmac CHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_event_log_service_time (service_name, created_at),
    KEY idx_event_log_category_time (category, created_at)
) ENGINE=InnoDB;
