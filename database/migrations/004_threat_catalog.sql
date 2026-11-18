CREATE TABLE IF NOT EXISTS ti_providers (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(40) NOT NULL UNIQUE,
    title VARCHAR(140) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    interval_minutes SMALLINT UNSIGNED NOT NULL DEFAULT 1440,
    next_run DATETIME NULL,
    last_success_at DATETIME NULL,
    checkpoint JSON NULL,
    INDEX (enabled,next_run)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_indicators (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    kind VARCHAR(12) NOT NULL,
    fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    display_value VARCHAR(2048) NOT NULL,
    host VARCHAR(255) NULL,
    ip_scope VARCHAR(20) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (kind,fingerprint),
    INDEX (kind,created_at),
    INDEX (host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_indicator_sources (
    indicator_id BIGINT UNSIGNED NOT NULL,
    provider_id INT UNSIGNED NOT NULL,
    category VARCHAR(40) NOT NULL,
    severity VARCHAR(15) NOT NULL,
    confidence TINYINT UNSIGNED NULL,
    malware_family VARCHAR(120) NULL,
    first_seen DATETIME NULL,
    last_seen DATETIME NULL,
    expires_at DATETIME NULL,
    verified_at DATETIME NULL,
    reference_text VARCHAR(1000) NULL,
    evidence JSON NOT NULL,
    evidence_sha256 CHAR(64) NOT NULL,
    parser_version VARCHAR(30) NOT NULL,
    retrieved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (indicator_id,provider_id),
    FOREIGN KEY (indicator_id) REFERENCES ti_indicators(id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id) REFERENCES ti_providers(id),
    INDEX (provider_id,retrieved_at),
    INDEX (expires_at,indicator_id),
    INDEX (category,indicator_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_vulnerabilities (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    cve VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    vendor VARCHAR(140) NULL,
    product VARCHAR(140) NULL,
    description TEXT NULL,
    cvss DECIMAL(3,1) NULL,
    cvss_vector VARCHAR(255) NULL,
    severity VARCHAR(15) NULL,
    published_at DATETIME NULL,
    modified_at DATETIME NULL,
    nvd_evidence JSON NULL,
    nvd_evidence_sha256 CHAR(64) NULL,
    nvd_retrieved_at DATETIME NULL,
    kev_added_on DATE NULL,
    kev_due_on DATE NULL,
    kev_ransomware VARCHAR(60) NULL,
    kev_title VARCHAR(255) NULL,
    kev_action TEXT NULL,
    kev_evidence JSON NULL,
    kev_evidence_sha256 CHAR(64) NULL,
    kev_retrieved_at DATETIME NULL,
    epss DECIMAL(9,8) NULL,
    epss_percentile DECIMAL(9,8) NULL,
    epss_on DATE NULL,
    epss_retrieved_at DATETIME NULL,
    INDEX (vendor,product),
    INDEX (kev_added_on),
    INDEX (published_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_advisories (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    provider_id INT UNSIGNED NOT NULL,
    fingerprint CHAR(64) NOT NULL,
    title VARCHAR(220) NOT NULL,
    publisher VARCHAR(120) NOT NULL,
    published_on DATE NULL,
    severity VARCHAR(15) NOT NULL,
    category VARCHAR(40) NULL,
    product VARCHAR(140) NULL,
    cve VARCHAR(32) NULL,
    summary TEXT NOT NULL,
    mitigation TEXT NULL,
    reference_text VARCHAR(1000) NULL,
    healthcare BOOLEAN NOT NULL DEFAULT FALSE,
    state VARCHAR(20) NOT NULL DEFAULT 'baru',
    assignee_id INT UNSIGNED NULL,
    analyst_note VARCHAR(2000) NULL,
    evidence_sha256 CHAR(64) NOT NULL,
    retrieved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider_id,fingerprint),
    FOREIGN KEY (provider_id) REFERENCES ti_providers(id),
    FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX (published_on),
    INDEX (cve)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_advisory_bookmarks (
    advisory_id BIGINT UNSIGNED NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    bookmarked BOOLEAN NOT NULL DEFAULT FALSE,
    read_at DATETIME NULL,
    PRIMARY KEY (advisory_id,user_id),
    FOREIGN KEY (advisory_id) REFERENCES ti_advisories(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_reference_domains (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    title VARCHAR(160) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_asset_vulnerabilities (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    asset_id INT UNSIGNED NOT NULL,
    vulnerability_id BIGINT UNSIGNED NOT NULL,
    state VARCHAR(25) NOT NULL DEFAULT 'potensial',
    basis VARCHAR(255) NOT NULL,
    due_on DATE NULL,
    assignee_id INT UNSIGNED NULL,
    note VARCHAR(2000) NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE (asset_id,vulnerability_id),
    FOREIGN KEY (asset_id) REFERENCES institutional_assets(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES ti_vulnerabilities(id),
    FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX (state,due_on)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_scan_results (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,
    client_id INT UNSIGNED NULL,
    kind VARCHAR(12) NOT NULL,
    display_value VARCHAR(2048) NOT NULL,
    facts JSON NOT NULL,
    priority TINYINT UNSIGNED NOT NULL,
    rule_version VARCHAR(20) NOT NULL,
    searched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (client_id) REFERENCES api_clients(id) ON DELETE SET NULL,
    INDEX (user_id,id),
    INDEX (kind,searched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_scan_matches (
    scan_id BIGINT UNSIGNED NOT NULL,
    position SMALLINT UNSIGNED NOT NULL,
    snapshot JSON NOT NULL,
    PRIMARY KEY (scan_id,position),
    FOREIGN KEY (scan_id) REFERENCES ti_scan_results(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_alerts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    dedup_key CHAR(64) NOT NULL UNIQUE,
    category VARCHAR(40) NOT NULL,
    title VARCHAR(220) NOT NULL,
    severity VARCHAR(15) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'baru',
    route VARCHAR(160) NOT NULL,
    assignee_id INT UNSIGNED NULL,
    acknowledged_by INT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX (status,severity,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_sync_jobs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    provider_id INT UNSIGNED NOT NULL,
    requested_by INT UNSIGNED NULL,
    action VARCHAR(20) NOT NULL DEFAULT 'sync',
    state VARCHAR(20) NOT NULL DEFAULT 'queued',
    attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_until DATETIME NULL,
    lease_token CHAR(32) NULL,
    checkpoint JSON NULL,
    received INT UNSIGNED NOT NULL DEFAULT 0,
    rejected INT UNSIGNED NOT NULL DEFAULT 0,
    unchanged INT UNSIGNED NOT NULL DEFAULT 0,
    last_message VARCHAR(255) NULL,
    preview JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (provider_id) REFERENCES ti_providers(id),
    FOREIGN KEY (requested_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX (state,next_attempt_at,id),
    INDEX (provider_id,state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_sync_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    job_id BIGINT UNSIGNED NOT NULL,
    state VARCHAR(20) NOT NULL,
    message VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES ti_sync_jobs(id) ON DELETE CASCADE,
    INDEX (job_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_transfers (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,
    action VARCHAR(12) NOT NULL,
    file_sha256 CHAR(64) NOT NULL,
    rows_total INT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_reports (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(48) NOT NULL UNIQUE,
    title VARCHAR(180) NOT NULL,
    kind VARCHAR(30) NOT NULL,
    user_id INT UNSIGNED NULL,
    approver_id INT UNSIGNED NULL,
    scan_id BIGINT UNSIGNED NULL,
    snapshot JSON NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (approver_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (scan_id) REFERENCES ti_scan_results(id) ON DELETE SET NULL,
    INDEX (approved_at,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS ti_settings (
    name VARCHAR(60) PRIMARY KEY,
    value VARCHAR(160) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
