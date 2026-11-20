CREATE TABLE template_versions (
    id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    proposed_by TEXT NOT NULL,
    approved_by TEXT,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX template_single_active ON template_versions(state) WHERE state='active';
PRAGMA user_version=2;
