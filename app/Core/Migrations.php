<?php
declare(strict_types=1);
namespace Sentinel\Core;

final class Migrations
{
    public static function run(callable $seed): void
    {
        $lock = 'sentinel-migrate:' . substr(hash('sha256', (string) query('SELECT DATABASE()')->fetchColumn()), 0, 40);
        if ((int) query('SELECT GET_LOCK(?,10)', [$lock])->fetchColumn() !== 1) {
            throw new \RuntimeException('Migrasi lain masih berjalan.');
        }
        try {
            db()->exec('CREATE TABLE IF NOT EXISTS schema_migrations (name VARCHAR(190) PRIMARY KEY) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
            foreach (glob(BASE . '/database/migrations/*.sql') as $file) {
                $name = basename($file);
                if (query('SELECT 1 FROM schema_migrations WHERE name=?', [$name])->fetchColumn()) {
                    continue;
                }
                foreach (explode(';', (string) file_get_contents($file)) as $sql) {
                    self::execute(trim($sql));
                }
                query('INSERT INTO schema_migrations VALUES (?)', [$name]);
            }
            $seed();
        } finally {
            query('SELECT RELEASE_LOCK(?)', [$lock]);
        }
    }

    private static function execute(string $sql): void
    {
        if ($sql === '') {
            return;
        }
        $sql = preg_replace('/^CREATE TABLE (?!IF NOT EXISTS )/i', 'CREATE TABLE IF NOT EXISTS ', $sql);
        // MySQL does not support ADD COLUMN IF NOT EXISTS. Check columns from completed DDL steps.
        if (preg_match('/^ALTER TABLE (\w+) ADD COLUMN (\w+) (.+) NULL$/iD', $sql, $parts)) {
            [, $table, $column, $type] = $parts;
            $existing = query('SELECT COLUMN_TYPE,IS_NULLABLE FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?', [$table, $column])->fetch();
            if ($existing) {
                $actual = preg_replace('/^int\(\d+\)/i', 'int', $existing['COLUMN_TYPE']);
                if (strcasecmp($actual, $type) !== 0 || $existing['IS_NULLABLE'] !== 'YES') {
                    throw new \RuntimeException("Kolom $table.$column berbeda dari definisi migrasi.");
                }
                return;
            }
        }
        db()->exec($sql);
    }
}
