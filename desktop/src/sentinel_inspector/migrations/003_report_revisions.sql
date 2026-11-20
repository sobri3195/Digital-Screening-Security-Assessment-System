CREATE TABLE inspection_report_revisions (
    inspection_id TEXT NOT NULL REFERENCES inspections(id),
    revision INTEGER NOT NULL,
    snapshot TEXT NOT NULL,
    PRIMARY KEY(inspection_id,revision)
);
PRAGMA user_version=3;
