<?php
declare(strict_types=1);
require dirname(__DIR__, 2) . '/app/Core/bootstrap.php';

$action = $argv[1] ?? '';
if (!in_array($action, ['seed', 'purge'], true)) {
    fwrite(STDERR, "Perintah: seed (kata sandi demo dari stdin) | purge DEMO\n");
    exit(2);
}
if ($action === 'purge' && ($argv[2] ?? '') !== 'DEMO') {
    fwrite(STDERR, "Ketik DEMO untuk konfirmasi penghapusan.\n");
    exit(2);
}
$tables = ['reports', 'security_incidents', 'security_findings', 'file_inspections', 'url_inspections', 'activities', 'institutional_assets', 'users'];
$db = db();
$db->beginTransaction();
try {
    if ($action === 'purge') {
        foreach ($tables as $table) {
            query("DELETE FROM $table WHERE demo = 1");
        }
        audit(null, 'hapus-demo', 'setup');
        $db->commit();
        echo "Data DEMO dihapus.\n";
        exit;
    }
    foreach ($tables as $table) {
        if (query("SELECT 1 FROM $table WHERE demo = 1 LIMIT 1")->fetchColumn()) {
            throw new RuntimeException('Hapus data DEMO yang ada sebelum menanam ulang.');
        }
    }
    $password = rtrim((string) fgets(STDIN), "\r\n");
    if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
        throw new RuntimeException('Kata sandi demo harus 12–72 byte.');
    }
    foreach (array_keys(require BASE . '/config/access.php') as $index => $role) {
        query('INSERT INTO users (title,username,password_hash,demo) VALUES (?,?,?,1)', ['DEMO ' . $role, 'demo-' . ($index + 1), password_hash($password, PASSWORD_DEFAULT)]);
        $user = (int) $db->lastInsertId();
        $count = query('INSERT INTO user_roles SELECT ?, id FROM roles WHERE title = ?', [$user, $role])->rowCount();
        if ($count !== 1) {
            throw new RuntimeException('Role belum siap. Jalankan migrasi.');
        }
    }
    $year = (int) date('Y');
    for ($i = 1; $i <= 100; $i++) {
        query('INSERT INTO institutional_assets (code,title,owner_unit,demo) VALUES (?,?,?,1)', ['DEMO-A-' . $i, 'DEMO Aset ' . $i, 'DEMO Unit']);
        if ($i <= 20) {
            query("INSERT INTO activities (code,title,activity_year,participant_count,held_on,state,demo) VALUES (?,?,?,?,CURDATE(),'dijadwalkan',1)", ['DEMO-K-' . $i, 'DEMO Kegiatan ' . $i, $year, 5 + $i]);
            query("INSERT INTO reports (code,title,source,notes,state,demo) VALUES (?,?, 'kegiatan', 'DEMO Ringkasan sintetis', 'draf',1)", ['DEMO-L-' . $i, 'DEMO Laporan ' . $i]);
        }
        if ($i <= 50) {
            $host = 'demo-' . $i . '.example.org';
            query('INSERT INTO url_inspections (title,host,indicators,demo) VALUES (?,?,?,1)', ['https://' . $host, $host, 'DEMO data sintetis']);
        }
        if ($i <= 30) {
            $name = 'DEMO file ' . $i;
            query("INSERT INTO file_inspections (title,mime,extension,bytes,md5_hash,sha256,mismatch,scan_status,demo) VALUES (?,'text/plain','txt',?,?,?,'Data demo','Belum diperiksa antivirus',1)",
                [$name . '.txt', strlen($name), md5($name), hash('sha256', $name)]);
        }
        if ($i <= 25) {
            query("INSERT INTO security_findings (title,category,severity,state,inspected_on,demo) VALUES (?,'DEMO Konfigurasi','rendah','draf',CURDATE(),1)", ['DEMO Temuan ' . $i]);
        }
        if ($i <= 15) {
            query("INSERT INTO security_incidents (title,category,severity,state,demo) VALUES (?,'lainnya','sedang','terbuka',1)", ['DEMO Insiden ' . $i]);
        }
    }
    audit(null, 'buat-demo', 'setup');
    $db->commit();
    echo "Data DEMO dibuat.\n";
} catch (Throwable $error) {
    $db->rollBack();
    fwrite(STDERR, ($error instanceof PDOException ? 'Tidak dapat mengubah data DEMO. Periksa dependensi data.' : $error->getMessage()) . PHP_EOL);
    exit(1);
}
