<?php
declare(strict_types=1);

use Sentinel\Core\DeploymentUnit;
use Sentinel\Core\Migrations;
use Sentinel\Services\Reports;
use Sentinel\Services\Threat\IntelligenceReports;
use Sentinel\Services\Threat\Store;

$command = $argv[1] ?? '';
if (in_array($command, ['migrate', 'unit-bind'], true)) {
    define('SENTINEL_UNIT_SETUP', true);
}
require dirname(__DIR__) . '/app/Core/bootstrap.php';

if ($command === 'key') {
    echo bin2hex(random_bytes(32)), PHP_EOL;
    exit;
}
if ($command === 'unit-bind') {
    DeploymentUnit::bind();
    echo "Unit terikat pada database dan penyimpanan.\n";
    exit;
}
if ($command !== 'migrate' && $command !== 'admin') {
    fwrite(STDERR, "Perintah: key | migrate | unit-bind | admin NAMA_PENGGUNA (kata sandi dari stdin)\n");
    exit(2);
}
if ($command === 'migrate') {
    Migrations::run(static function (): void {
        Store::transaction(seed_base_roles(...));
        Sentinel\Services\Threat\Setup::seed();
        Sentinel\Services\Ai\Setup::seed();
        Reports::backfillFinalDocuments();
        IntelligenceReports::backfillFinalDocuments();
    });
    echo "Migrasi dan konfigurasi awal selesai.\n";
    exit;
}

function seed_base_roles(): void
{
    $roles = require BASE . '/config/access.php';
    $permissions = ['dashboard.read', 'system.read', 'report.approved', 'report.approve', 'technical.approve'];
    foreach (require BASE . '/config/modules.php' as $module) {
        foreach (['read', 'write'] as $action) {
            $permissions[] = $module[2] . '.' . $action;
        }
    }
    foreach (array_unique($permissions) as $permission) {
        query('INSERT IGNORE INTO permissions VALUES (?)', [$permission]);
    }
    foreach ($roles as $role => $grants) {
        if (query('INSERT IGNORE INTO roles (title) VALUES (?)', [$role])->rowCount() === 0) {
            continue;
        }
        $id = (int) db()->lastInsertId();
        foreach ($grants === ['*'] ? array_unique($permissions) : $grants as $permission) {
            query('INSERT INTO role_permissions VALUES (?, ?)', [$id, $permission]);
        }
    }
    foreach (['Pembaruan sistem operasi', 'Pembaruan antivirus', 'Enkripsi penyimpanan', 'Screen lock', 'Firewall', 'Autentikasi dua faktor', 'Backup data', 'Pengaturan keamanan jaringan', 'Software sah', 'Perlindungan phishing'] as $item) {
        query('INSERT IGNORE INTO checklist_items (title) VALUES (?)', [$item]);
    }
}
$username = $argv[2] ?? '';
$password = rtrim((string) fgets(STDIN), "\r\n");
if (!preg_match('/^[a-zA-Z0-9_.-]{3,100}$/D', $username) || strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
    fwrite(STDERR, "Nama pengguna tidak valid atau kata sandi harus berisi 12–72 byte.\n");
    exit(2);
}
db()->beginTransaction();
query('INSERT INTO users (title, username, password_hash) VALUES (?, ?, ?)', ['Administrator', $username, password_hash($password, PASSWORD_DEFAULT)]);
if (query("INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles WHERE title = 'Super Administrator'", [(int) db()->lastInsertId()])->rowCount() !== 1) {
    db()->rollBack();
    throw new RuntimeException('Jalankan migrasi sebelum membuat administrator.');
}
db()->commit();
echo "Administrator dibuat.\n";
