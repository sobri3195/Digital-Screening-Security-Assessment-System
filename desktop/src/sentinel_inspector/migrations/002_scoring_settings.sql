ALTER TABLE inspections ADD COLUMN scoring_rule TEXT REFERENCES scoring_rules(version);
UPDATE inspections SET scoring_rule='posture-1';
CREATE TABLE inspector_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO inspector_settings VALUES ('active_scoring_rule','posture-1');
PRAGMA user_version=2;
