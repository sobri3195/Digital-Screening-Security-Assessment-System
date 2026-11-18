CREATE TABLE assets (
    id TEXT PRIMARY KEY, code TEXT NOT NULL COLLATE NOCASE UNIQUE, name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('windows','android','ios','usb','other')),
    owner_unit TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE inspection_authorizations (
    id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(id),
    operator_code TEXT NOT NULL, reference TEXT NOT NULL, scope TEXT NOT NULL,
    authorized_at TEXT NOT NULL, local_host_confirmed INTEGER NOT NULL CHECK(local_host_confirmed IN (0,1))
);
CREATE TABLE inspections (
    id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE REFERENCES inspection_authorizations(id),
    mode TEXT NOT NULL CHECK(mode IN ('quick','comprehensive','custom')),
    status TEXT NOT NULL CHECK(status IN ('ready','running','review','closed','cancelled')),
    created_at TEXT NOT NULL, started_at TEXT, ended_at TEXT, reviewer_code TEXT
);
CREATE TABLE inspection_tasks (
    inspection_id TEXT NOT NULL REFERENCES inspections(id), module TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','running','complete','unavailable','failed','cancelled')),
    notice TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL, PRIMARY KEY(inspection_id,module)
);
CREATE TABLE technical_evidence (
    id TEXT PRIMARY KEY, inspection_id TEXT NOT NULL REFERENCES inspections(id),
    module TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT NOT NULL,
    payload TEXT NOT NULL, sha256 TEXT NOT NULL
);
CREATE TABLE findings (
    id TEXT PRIMARY KEY, inspection_id TEXT NOT NULL REFERENCES inspections(id),
    evidence_id TEXT NOT NULL REFERENCES technical_evidence(id),
    category TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
    status TEXT NOT NULL, recommendation TEXT NOT NULL, review_note TEXT NOT NULL DEFAULT '',
    reviewer_code TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY, inspection_id TEXT REFERENCES inspections(id), event TEXT NOT NULL,
    detail TEXT NOT NULL, occurred_at TEXT NOT NULL, previous_sha256 TEXT NOT NULL, sha256 TEXT NOT NULL
);
CREATE TABLE usb_events (
    id INTEGER PRIMARY KEY, event TEXT NOT NULL, category TEXT NOT NULL, manufacturer TEXT NOT NULL,
    model TEXT NOT NULL, driver_status TEXT NOT NULL, observed_at TEXT NOT NULL
);
CREATE TABLE yara_rules (
    id TEXT PRIMARY KEY, label TEXT NOT NULL, version TEXT NOT NULL, sha256 TEXT NOT NULL UNIQUE,
    rules TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)), created_at TEXT NOT NULL, UNIQUE(label,version)
);
CREATE TABLE intelligence_imports (
    id INTEGER PRIMARY KEY, source TEXT NOT NULL, checksum TEXT NOT NULL UNIQUE,
    imported_at TEXT NOT NULL, source_updated_at TEXT
);
CREATE TABLE indicators (
    kind TEXT NOT NULL, fingerprint TEXT NOT NULL, display_value TEXT NOT NULL, source TEXT NOT NULL,
    category TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER, first_seen TEXT, last_seen TEXT,
    expires_at TEXT, family TEXT, reference TEXT, import_id INTEGER NOT NULL REFERENCES intelligence_imports(id),
    PRIMARY KEY(kind,fingerprint,source)
);
CREATE TABLE vulnerabilities (
    cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, cvss REAL, severity TEXT,
    kev_added TEXT, kev_due TEXT, epss REAL, epss_on TEXT, metadata TEXT NOT NULL,
    import_id INTEGER NOT NULL REFERENCES intelligence_imports(id)
);
CREATE TABLE affected_products (
    cve TEXT NOT NULL REFERENCES vulnerabilities(cve) ON DELETE CASCADE,
    vendor TEXT NOT NULL, product TEXT NOT NULL, PRIMARY KEY(vendor,product,cve)
);
CREATE TABLE advisories (
    reference_id TEXT PRIMARY KEY, publisher TEXT NOT NULL, title TEXT NOT NULL, published_at TEXT,
    summary TEXT NOT NULL, cve TEXT, reference TEXT, import_id INTEGER NOT NULL REFERENCES intelligence_imports(id)
);
CREATE TABLE scoring_rules (
    version TEXT PRIMARY KEY, weights TEXT NOT NULL, minimum_coverage INTEGER NOT NULL
);
INSERT INTO scoring_rules VALUES ('posture-1','{"os":20,"updates":20,"antivirus":15,"encryption":15,"configuration":15,"mitigation":15}',70);
CREATE TABLE reports (
    id TEXT PRIMARY KEY, inspection_id TEXT NOT NULL REFERENCES inspections(id), kind TEXT NOT NULL,
    format TEXT NOT NULL, file_sha256 TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX evidence_inspection ON technical_evidence(inspection_id,observed_at);
CREATE INDEX findings_inspection ON findings(inspection_id,status);
CREATE INDEX audit_inspection ON audit_events(inspection_id,sequence);
CREATE INDEX vulns_product ON vulnerabilities(vendor,product);
CREATE INDEX advisories_publisher ON advisories(publisher,published_at);
PRAGMA user_version=1;
