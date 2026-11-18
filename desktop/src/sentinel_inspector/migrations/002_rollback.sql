DROP TABLE inspector_settings;
ALTER TABLE inspections DROP COLUMN scoring_rule;
PRAGMA user_version=1;
