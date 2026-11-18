<?php
declare(strict_types=1);
namespace Sentinel\Services;

use Sentinel\Core\Http;

final class Backup
{
    private const TABLES = [
        'activity_periods', 'activities', 'activity_history', 'institutional_assets', 'asset_maintenance', 'inspection_schedules', 'education',
        'url_inspections', 'security_checklists', 'checklist_results', 'security_findings', 'evidence_metadata',
        'security_incidents', 'incident_timelines', 'reports', 'report_approvals', 'notifications', 'system_settings',
    ];
    private const LIMIT = 32 * 1024 * 1024;

    public static function create(?int $user): int
    {
        if (!is_dir(BASE . '/storage/backups') && !mkdir(BASE . '/storage/backups', 0700, true) && !is_dir(BASE . '/storage/backups')) {
            throw new \RuntimeException('Penyimpanan backup tidak tersedia.');
        }
        $title = 'sentinel-' . bin2hex(random_bytes(16)) . '.backup';
        $target = BASE . '/storage/backups/' . $title;
        $tables = [];
        $size = 0;
        db()->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        db()->beginTransaction();
        try {
            foreach (self::TABLES as $table) {
                $tables[$table] = [];
                $rows = query("SELECT * FROM `$table`");
                foreach ($rows as $row) {
                    $size += strlen(json_encode($row, JSON_THROW_ON_ERROR)) + 1;
                    if ($size > self::LIMIT) {
                        throw new Http(422, 'Data melampaui kapasitas backup aplikasi.');
                    }
                    $tables[$table][] = $row;
                }
            }
            $sealed = Secrets::seal('sentinel-backup-v2:' . json_encode($tables, JSON_THROW_ON_ERROR));
            $original = umask(0077);
            try {
                if (file_put_contents($target, $sealed, LOCK_EX) !== strlen($sealed)) {
                    throw new \RuntimeException('Backup tidak dapat ditulis.');
                }
            } finally {
                umask($original);
            }
            query("INSERT INTO backup_history (title,checksum,result) VALUES (?,?, 'berhasil')", [$title, hash('sha256', $sealed)]);
            $id = (int) db()->lastInsertId();
            audit($user, 'backup', 'backup');
            db()->commit();
            return $id;
        } catch (\Throwable $error) {
            db()->rollBack();
            if (is_file($target)) {
                unlink($target);
            }
            throw $error;
        }
    }

    public static function download(int $id, int $user): never
    {
        [$backup, $data] = self::read($id);
        audit($user, 'download', 'backup');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $backup['title'] . '"');
        echo $data;
        exit;
    }

    public static function restore(int $id, int $user): void
    {
        [, $sealed] = self::read($id);
        $payload = Secrets::open($sealed);
        if (!str_starts_with($payload, 'sentinel-backup-v2:')) {
            throw new Http(422, 'Format backup tidak dikenali.');
        }
        $tables = json_decode(substr($payload, strlen('sentinel-backup-v2:')), true, 512, JSON_THROW_ON_ERROR);
        if (array_keys($tables) !== self::TABLES) {
            throw new Http(422, 'Skema backup tidak cocok.');
        }
        db()->beginTransaction();
        try {
            // Phase 1 backup files exclude intel data. Preserve their locally linked assets or fail atomically.
            $assetLinks = query('SELECT av.*, a.code AS current_code FROM ti_asset_vulnerabilities av
                JOIN institutional_assets a ON a.id=av.asset_id FOR UPDATE')->fetchAll();
            $restoredAssets = array_column($tables['institutional_assets'], 'code', 'id');
            foreach ($assetLinks as $link) {
                if (($restoredAssets[$link['asset_id']] ?? null) !== $link['current_code']) {
                    throw new Http(422, 'Cadangan tidak mempertahankan aset yang dirujuk temuan intelijen.');
                }
            }
            foreach (array_reverse(self::TABLES) as $table) {
                query("DELETE FROM `$table`");
            }
            foreach ($tables as $table => $rows) {
                $trusted = query("SHOW COLUMNS FROM `$table`")->fetchAll(\PDO::FETCH_COLUMN);
                foreach ($rows as $row) {
                    if (array_keys($row) !== $trusted) {
                        throw new Http(422, 'Struktur baris backup tidak cocok.');
                    }
                    $columns = '`' . implode('`, `', $trusted) . '`';
                    $parameters = implode(', ', array_fill(0, count($trusted), '?'));
                    query("INSERT INTO `$table` ($columns) VALUES ($parameters)", array_values($row));
                }
            }
            foreach ($assetLinks as $link) {
                unset($link['current_code']);
                query('INSERT INTO ti_asset_vulnerabilities (id,asset_id,vulnerability_id,state,basis,due_on,assignee_id,note,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)', array_values($link));
            }
            audit($user, 'restore', 'backup');
            db()->commit();
        } catch (\Throwable $error) {
            db()->rollBack();
            throw $error;
        }
    }

    private static function read(int $id): array
    {
        $record = query('SELECT * FROM backup_history WHERE id = ?', [$id])->fetch();
        if (!$record || !preg_match('/^sentinel-[a-f0-9]{32}\.backup$/D', $record['title'])) {
            throw new Http(404, 'Backup tidak ditemukan.');
        }
        $path = BASE . '/storage/backups/' . $record['title'];
        $data = is_file($path) ? file_get_contents($path, false, null, 0, 2 * self::LIMIT) : false;
        if (!is_string($data) || !hash_equals($record['checksum'], hash('sha256', $data))) {
            throw new Http(422, 'Verifikasi integritas backup gagal.');
        }
        return [$record, $data];
    }
}
