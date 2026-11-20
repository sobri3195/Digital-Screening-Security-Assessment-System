CREATE TABLE IF NOT EXISTS ti_incident_links (
    incident_id INT UNSIGNED NOT NULL,
    vulnerability_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY(incident_id,vulnerability_id),
    FOREIGN KEY(incident_id) REFERENCES security_incidents(id) ON DELETE CASCADE,
    FOREIGN KEY(vulnerability_id) REFERENCES ti_vulnerabilities(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS ti_desktop_results (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    asset_id INT UNSIGNED NOT NULL,
    client_id INT UNSIGNED NULL,
    session_id CHAR(32) NOT NULL,
    revision INT UNSIGNED NOT NULL,
    report_sha256 CHAR(64) NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    score TINYINT UNSIGNED NULL,
    coverage TINYINT UNSIGNED NOT NULL,
    finding_count INT UNSIGNED NOT NULL,
    tasks_total TINYINT UNSIGNED NOT NULL,
    tasks_completed TINYINT UNSIGNED NOT NULL,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id,revision),
    FOREIGN KEY(asset_id) REFERENCES institutional_assets(id) ON DELETE CASCADE,
    FOREIGN KEY(client_id) REFERENCES api_clients(id) ON DELETE SET NULL
) ENGINE=InnoDB;
