CREATE TABLE sources (
    code TEXT PRIMARY KEY, title TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
);
CREATE TABLE documents (
    id TEXT PRIMARY KEY, source_code TEXT NOT NULL REFERENCES sources(code),
    title TEXT NOT NULL, version TEXT NOT NULL, published TEXT NOT NULL, reference TEXT NOT NULL,
    classification TEXT NOT NULL, content TEXT NOT NULL, facts TEXT NOT NULL, checksum TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','approved','archived')),
    index_status TEXT NOT NULL DEFAULT 'pending', submitted_by TEXT NOT NULL, approved_by TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(source_code,title,version), UNIQUE(source_code,checksum)
);
CREATE TABLE chunks (
    id INTEGER PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    position INTEGER NOT NULL, body TEXT NOT NULL, UNIQUE(document_id,position)
);
CREATE VIRTUAL TABLE chunks_fts USING fts5(body, content='', tokenize='unicode61 remove_diacritics 2');
CREATE TABLE embeddings (
    chunk_id INTEGER NOT NULL REFERENCES chunks(id) ON DELETE CASCADE,
    model_digest TEXT NOT NULL, size INTEGER NOT NULL, vector BLOB NOT NULL,
    PRIMARY KEY(chunk_id,model_digest)
);
CREATE TABLE models (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, digest TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('inference','embedding')),
    license_reference TEXT NOT NULL, options TEXT NOT NULL, approved_by TEXT NOT NULL, approved_at TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0,1)),
    UNIQUE(name,digest,role)
);
CREATE UNIQUE INDEX active_model_per_role ON models(role) WHERE active=1;
CREATE TABLE jobs (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, input_checksum TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','processing','completed','failed','cancelled','requires_review')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, available_at REAL NOT NULL,
    lease TEXT, lease_until REAL, attempts INTEGER NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0,
    result TEXT, error_code TEXT, model_name TEXT, model_digest TEXT, metrics TEXT, priority INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX live_job_dedup ON jobs(owner,kind,input_checksum) WHERE state IN ('pending','processing');
CREATE INDEX ready_jobs ON jobs(state,available_at,priority,created_at);
CREATE INDEX owner_jobs ON jobs(owner,created_at DESC);
CREATE TABLE reviews (
    id INTEGER PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    reviewer TEXT NOT NULL, decision TEXT NOT NULL, reviewed_at TEXT NOT NULL
);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT,
    outcome TEXT NOT NULL, occurred_at TEXT NOT NULL
);
CREATE INDEX audit_recency ON audit(occurred_at);
CREATE TABLE limits (
    actor TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(actor,window)
);
PRAGMA user_version=1;
