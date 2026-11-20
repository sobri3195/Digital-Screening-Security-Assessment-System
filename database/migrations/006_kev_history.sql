CREATE TABLE IF NOT EXISTS ti_kev_history (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    vulnerability_id BIGINT UNSIGNED NOT NULL,
    sync_job_id BIGINT UNSIGNED NOT NULL,
    status VARCHAR(12) NOT NULL,
    evidence JSON NOT NULL,
    evidence_sha256 CHAR(64) NOT NULL,
    observed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES ti_vulnerabilities(id),
    INDEX (vulnerability_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
