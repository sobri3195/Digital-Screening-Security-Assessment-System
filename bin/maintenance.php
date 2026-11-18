<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/Core/bootstrap.php';

use Sentinel\Services\Backup;

if (($argv[1] ?? '') === 'backup') {
    echo Backup::create(null), PHP_EOL;
    exit;
}
if (($argv[1] ?? '') !== 'retention') {
    fwrite(STDERR, "Perintah: backup | retention\n");
    exit(2);
}
$files = query('SELECT id,storage_name FROM file_inspections WHERE retained_until <= NOW() AND storage_name IS NOT NULL')->fetchAll();
foreach ($files as $file) {
    if (preg_match('/^[a-f0-9]{32}$/D', $file['storage_name'])) {
        $path = BASE . '/storage/uploads/' . $file['storage_name'];
        if (!is_file($path) || unlink($path)) {
            query('UPDATE file_inspections SET storage_name = NULL WHERE id = ?', [$file['id']]);
        }
    }
}
query('DELETE FROM login_attempts WHERE created_at < NOW() - INTERVAL 90 DAY');
query('DELETE FROM user_sessions WHERE last_seen < NOW() - INTERVAL 1 DAY');
query('DELETE FROM api_tokens WHERE expires_at < NOW()');
query("DELETE FROM api_limits WHERE (bucket LIKE 'login-user:%' AND minute < ?) OR (bucket NOT LIKE 'login-user:%' AND minute < ?)", [intdiv(time() - 86400, 900), intdiv(time() - 86400, 60)]);
foreach (query('SELECT id,title FROM backup_history WHERE created_at < NOW() - INTERVAL 30 DAY')->fetchAll() as $backup) {
    if (preg_match('/^sentinel-[a-f0-9]{32}\.backup$/D', $backup['title'])) {
        $file = BASE . '/storage/backups/' . $backup['title'];
        if (!is_file($file) || unlink($file)) {
            query('DELETE FROM backup_history WHERE id = ?', [$backup['id']]);
        }
    }
}
audit(null, 'retensi', 'maintenance');
