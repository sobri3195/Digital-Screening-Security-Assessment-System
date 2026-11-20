<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Core/bootstrap.php';

use Sentinel\Core\Migrations;

if (!str_starts_with(config('DB_NAME'), 'sentinel_phase_')
    || (int) query('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')->fetchColumn() !== 0) {
    throw new RuntimeException('Gunakan database disposable kosong dengan prefiks sentinel_phase_.');
}
db()->exec(explode(';', (string) file_get_contents(BASE . '/database/migrations/001_initial.sql'), 2)[0]);
query("INSERT INTO roles (title) VALUES ('TEST role retained')");
Migrations::run(static function (): void {});
query("DELETE FROM schema_migrations WHERE name IN ('002_report_snapshot.sql','005_report_documents.sql')");
Migrations::run(static function (): void {});
if (!query("SELECT id FROM roles WHERE title='TEST role retained'")->fetchColumn()
    || (int) query('SELECT COUNT(*) FROM schema_migrations')->fetchColumn() !== count(glob(BASE . '/database/migrations/*.sql'))) {
    throw new RuntimeException('Migrasi ulang tidak mempertahankan data atau ledger.');
}
echo "Migrasi melanjutkan pembuatan tabel dan kolom tanpa menghapus data.\n";
