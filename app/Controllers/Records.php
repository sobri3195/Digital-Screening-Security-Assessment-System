<?php
declare(strict_types=1);
namespace Sentinel\Controllers;

use Sentinel\Core\Auth;
use Sentinel\Core\Http;
use Sentinel\Services\Inspection;
use Sentinel\Services\Reports;

final class Records
{
    public const CHECK_STATES = ['memenuhi', 'tidak_memenuhi', 'belum_diperiksa', 'tidak_berlaku'];

    public static function view(string $table, array $module, array $user, bool $archive = false): array
    {
        [$title, , $permission, $fields] = $module;
        $approvalOnly = $table === 'reports' && !Auth::allows($user, 'report.read') && Auth::allows($user, 'report.approved');
        if (!$approvalOnly) {
            Auth::require($user, $permission . '.read');
        }
        if ($approvalOnly && $archive) {
            throw new Http(403, 'Arsip laporan memerlukan izin tambahan.');
        }
        $write = !$archive && Auth::allows($user, $permission . '.write');
        $special = $module['special'] ?? '';
        $rule = $table === 'system_settings' ? "title <> 'institution_logo'" : ($archive ? "state = 'arsip'" : ($approvalOnly ? "state = 'disetujui'" : ($table === 'reports' ? "state <> 'arsip'" : '1=1')));
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            Auth::require($user, $permission . '.write');
            self::save($table, $module, $user);
            $_SESSION['notice'] = 'Perubahan tersimpan.';
            Http::redirect('/m/' . $table);
        }
        $columns = implode(', ', array_keys($fields));
        $search = text_input($_GET, 'q');
        $state = text_input($_GET, 'state');
        $filters = [];
        if ($search !== '') {
            $column = array_key_exists('title', $fields) ? 'title' : array_key_first($fields);
            $rule .= " AND $column LIKE ?";
            $filters[] = '%' . mb_substr($search, 0, 160) . '%';
        }
        if ($state !== '' && isset($fields['state'])) {
            $rule .= ' AND state = ?';
            $filters[] = $state;
        }
        if (text_input($_GET, 'export') === 'csv' && (($module['csv'] ?? false) || $table === 'url_inspections')) {
            audit((int) $user['id'], 'export', $table);
            header('Content-Type: text/csv; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . $table . '.csv"');
            $out = fopen('php://output', 'wb');
            fputcsv($out, array_keys($fields), ',', '"', '');
            $rows = query("SELECT $columns FROM $table WHERE $rule ORDER BY id", $filters);
            while ($row = $rows->fetch()) {
                foreach ($row as &$cell) {
                    if (is_string($cell) && preg_match('/^[\x00-\x20]*[=+@-]|^[\t\r\n]/', $cell)) {
                        $cell = "'" . $cell;
                    }
                }
                unset($cell);
                fputcsv($out, $row, ',', '"', '');
            }
            exit;
        }
        $page = min(100000, max(1, (int) text_input($_GET, 'page')));
        $total = (int) query("SELECT COUNT(*) FROM $table WHERE $rule", $filters)->fetchColumn();
        $offset = ($page - 1) * 20;
        $rows = query("SELECT id, $columns, created_at FROM $table WHERE $rule ORDER BY id DESC LIMIT 20 OFFSET $offset", $filters)->fetchAll();
        $record = [];
        $id = (int) text_input($_GET, 'id');
        if ($id > 0) {
            $revisionFields = $special === 'report' ? ',revision_of,revision_reason,user_id' : '';
            $record = query("SELECT id, $columns, created_at$revisionFields FROM $table WHERE id = ? AND $rule", [$id, ...$filters])->fetch() ?: [];
            if (!$record) {
                throw new Http(404, 'Data tidak ditemukan.');
            }
        }
        $references = [];
        foreach ($fields as $key => $definition) {
            [, $type, $source] = array_pad(explode(':', $definition), 3, '');
            if ($type === 'ref') {
                $references[$key] = query("SELECT id, title FROM $source ORDER BY title")->fetchAll(\PDO::FETCH_KEY_PAIR);
            }
        }
        $extras = match ($special) {
            'checklist' => ['items' => query('SELECT id, title FROM checklist_items ORDER BY id')->fetchAll(), 'results' => $id ? query('SELECT item_id, state FROM checklist_results WHERE checklist_id = ?', [$id])->fetchAll(\PDO::FETCH_KEY_PAIR) : []],
            'incident' => ['history' => $id ? query('SELECT notes, created_at FROM incident_timelines WHERE incident_id = ? ORDER BY id DESC', [$id])->fetchAll() : []],
            'users' => $write ? ['options' => query('SELECT id, title FROM roles ORDER BY title')->fetchAll(\PDO::FETCH_KEY_PAIR), 'selected' => query('SELECT role_id FROM user_roles WHERE user_id = ?', [$id])->fetchAll(\PDO::FETCH_COLUMN)] : [],
            'roles' => $write ? ['options' => array_combine($p = query('SELECT code FROM permissions ORDER BY code')->fetchAll(\PDO::FETCH_COLUMN), $p), 'selected' => query('SELECT permission_code FROM role_permissions WHERE role_id = ?', [$id])->fetchAll(\PDO::FETCH_COLUMN)] : [],
            default => match ($table) {
                'institutional_assets' => ['history' => $id ? query('SELECT notes, created_at FROM asset_maintenance WHERE asset_id = ? ORDER BY id DESC', [$id])->fetchAll() : []],
                'activities' => ['history' => $id ? query('SELECT notes, created_at FROM activity_history WHERE activity_id = ? ORDER BY id DESC', [$id])->fetchAll() : []],
                default => [],
            },
        };
        return compact('title', 'module', 'table', 'fields', 'write', 'rows', 'record', 'special', 'page', 'total', 'search', 'state', 'references', 'extras', 'archive');
    }

    private static function fields(array $fields, array $input): array
    {
        $data = [];
        foreach ($fields as $key => $definition) {
            [, $type, $options] = array_pad(explode(':', $definition), 3, '');
            $value = text_input($input, $key);
            if ($value === '') {
                $data[$key] = null;
                continue;
            }
            $length = $type === 'long' ? 10000 : 255;
            $invalid = !mb_check_encoding($value, 'UTF-8') || mb_strlen($value) > $length
                || ($type === 'select' && !in_array($value, explode(',', $options), true))
                || (in_array($type, ['ref', 'number'], true) && !preg_match('/^\d{1,9}$/D', $value))
                || ($key === 'activity_year' && ((int) $value < 1900 || (int) $value > 2200))
                || ($type === 'date' && (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $value, $parts)
                    || !checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1])));
            if ($invalid) {
                throw new Http(422, 'Nilai tidak valid untuk kolom ' . explode(':', $definition)[0] . '.');
            }
            $data[$key] = $value;
        }
        foreach (['title' => 160, 'code' => 100, 'username' => 100] as $key => $length) {
            if (array_key_exists($key, $data) && ($data[$key] === null || mb_strlen($data[$key]) > $length)) {
                throw new Http(422, 'Kolom ' . $key . ' wajib diisi dengan panjang yang valid.');
            }
        }
        if (isset($data['starts_on'], $data['ends_on']) && $data['starts_on'] > $data['ends_on']) {
            throw new Http(422, 'Tanggal selesai harus sama atau setelah tanggal mulai.');
        }
        return $data;
    }

    private static function put(string $table, array $data, int $id): int
    {
        $keys = array_keys($data);
        if ($id) {
            $assignment = implode(' = ?, ', $keys) . ' = ?';
            query("UPDATE $table SET $assignment WHERE id = ?", [...array_values($data), $id]);
            return $id;
        }
        $columns = implode(', ', $keys);
        $params = implode(', ', array_fill(0, count($keys), '?'));
        query("INSERT INTO $table ($columns) VALUES ($params)", array_values($data));
        return (int) db()->lastInsertId();
    }

    private static function save(string $table, array $module, array $user): void
    {
        $special = $module['special'] ?? '';
        $userId = (int) $user['id'];
        $fields = $module[3];
        if ($special === 'url') {
            $data = Inspection::url(text_input($_POST, 'title'));
            self::put($table, $data + ['user_id' => $userId], 0);
            audit($userId, 'buat', $table);
            return;
        }
        if ($special === 'file') {
            Inspection::upload($_FILES['file'] ?? [], $userId);
            audit($userId, 'upload', $table);
            return;
        }
        if (in_array($special, ['readonly', 'backup'], true)) {
            throw new Http(405, 'Tindakan tidak tersedia.');
        }
        $id = (int) text_input($_POST, 'id');
        $action = text_input($_POST, 'action');
        db()->beginTransaction();
        try {
            if ($action === 'import' && ($module['csv'] ?? false)) {
                self::import($table, $fields);
                audit($userId, 'import', $table);
                db()->commit();
                return;
            }
            $previous = $id ? query("SELECT * FROM $table WHERE id = ? FOR UPDATE", [$id])->fetch() : null;
            if ($id && !$previous) {
                throw new Http(404, 'Data tidak ditemukan.');
            }
            if ($special === 'report' && $action === 'revisi') {
                self::reportRevision($previous, $userId);
                db()->commit();
                return;
            }
            if ($action === 'hapus' && in_array($table, ['institutional_assets', 'education', 'inspection_schedules', 'activity_periods'], true) && $id) {
                query("DELETE FROM $table WHERE id = ?", [$id]);
                audit($userId, 'hapus', $table);
                db()->commit();
                return;
            }
            $reportAction = $special === 'report' ? match ($action) {
                'setujui' => 'disetujui', 'kembalikan' => 'draf', 'arsipkan' => 'arsip',
                default => null,
            } : null;
            if ($reportAction !== null && ($previous['state'] ?? null) !== ($reportAction === 'arsip' ? 'disetujui' : 'diajukan')) {
                throw new Http(422, 'Tindakan tidak sesuai dengan status laporan.');
            }
            $data = $reportAction === null ? self::fields($fields, $_POST) : ['state' => $reportAction];
            if ($table === 'system_settings' && (($data['title'] ?? '') === 'institution_logo' || ($previous['title'] ?? '') === 'institution_logo')) {
                throw new Http(422, 'Gunakan formulir logo institusi.');
            }
            if ($special === 'users') {
                if (!preg_match('/^[a-zA-Z0-9_.-]{3,100}$/D', $data['username']) || $data['active'] === null) {
                    throw new Http(422, 'Nama pengguna atau status tidak valid.');
                }
                if ($id === $userId) {
                    throw new Http(422, 'Gunakan halaman profil untuk mengubah akun Anda.');
                }
                $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
                if (!$id) {
                    if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
                        throw new Http(422, 'Kata sandi awal harus berisi 12–72 byte.');
                    }
                    $data['password_hash'] = password_hash($password, PASSWORD_DEFAULT);
                } elseif ($password !== '') {
                    Auth::setPassword($id, $password);
                }
                if ($id && $data['active'] === '0') {
                    $data['auth_version'] = (int) $previous['auth_version'] + 1;
                    query('DELETE FROM user_sessions WHERE user_id = ?', [$id]);
                }
            }
            if ($special === 'roles' && ($previous['title'] ?? '') === 'Super Administrator') {
                throw new Http(422, 'Role Super Administrator dilindungi.');
            }
            if ($special === 'clients') {
                if ($data['active'] === null) {
                    throw new Http(422, 'Pilih status klien.');
                }
                $scopes = array_values(array_filter(array_map('trim', explode(',', $data['scopes'] ?? ''))));
                if (array_diff($scopes, Api::scopes())) {
                    throw new Http(422, 'Scope API tidak dikenal.');
                }
                $data['scopes'] = implode(',', $scopes);
                if ($id && $data['active'] === '0') {
                    query('DELETE FROM api_tokens WHERE client_id = ?', [$id]);
                }
                if (!$id || $action === 'rotasi') {
                    $secret = bin2hex(random_bytes(32));
                    $data['secret_hash'] = password_hash($secret, PASSWORD_DEFAULT);
                    if ($id) {
                        query('DELETE FROM api_tokens WHERE client_id = ?', [$id]);
                    }
                }
            }
            if (in_array($special, ['finding', 'incident', 'report'], true)) {
                self::workflow($special, $data, $previous, $user);
            }
            $approveReport = $special === 'report' && $data['state'] === 'disetujui';
            if ($approveReport) {
                $data['result_snapshot'] = json_encode(Reports::results($previous), JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
            }
            $saved = self::put($table, $data, $id);
            if ($special === 'users' || $special === 'roles') {
                self::assign($special, $saved);
            }
            if ($special === 'checklist') {
                foreach (query('SELECT id FROM checklist_items')->fetchAll(\PDO::FETCH_COLUMN) as $item) {
                    $state = text_input(is_array($_POST['check'] ?? null) ? $_POST['check'] : [], (string) $item) ?: 'belum_diperiksa';
                    if (!in_array($state, self::CHECK_STATES, true)) {
                        throw new Http(422, 'Status checklist tidak valid.');
                    }
                    query('INSERT INTO checklist_results VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE state = VALUES(state)', [$saved, $item, $state]);
                }
            }
            if ($approveReport) {
                query('INSERT INTO report_approvals (report_id,user_id) VALUES (?,?)', [$saved, $userId]);
                Reports::freeze($saved);
                query("INSERT INTO notifications (title,message,state) VALUES (?,?, 'baru')", ['Laporan disetujui', 'Laporan ' . $previous['code'] . ' telah disetujui.']);
            }
            if ($special === 'incident' || in_array($table, ['activities', 'institutional_assets'], true)) {
                $note = text_input($_POST, 'history_note');
                if ($special === 'incident' || $table === 'activities') {
                    $stateChange = ($previous['state'] ?? null) !== ($data['state'] ?? null) ? 'Status: ' . ($data['state'] ?? 'belum ditetapkan') : '';
                    $note = trim($stateChange . "\n" . $note);
                }
                if ($note !== '') {
                    if (mb_strlen($note) > 10000) {
                        throw new Http(422, 'Catatan riwayat terlalu panjang.');
                    }
                    $history = match ($table) {
                        'security_incidents' => 'incident_timelines (incident_id,user_id,notes)',
                        'institutional_assets' => 'asset_maintenance (asset_id,user_id,notes)',
                        'activities' => 'activity_history (activity_id,user_id,notes)',
                    };
                    query("INSERT INTO $history VALUES (?, ?, ?)", [$saved, $userId, $note]);
                }
            }
            $auditAction = in_array($special, ['users', 'roles'], true) ? 'kelola-hak-akses' : ($id ? 'ubah' : 'buat');
            audit($userId, $auditAction, $table);
            db()->commit();
            if (isset($secret)) {
                $_SESSION['client_secret'] = ['id' => $saved, 'secret' => $secret];
            }
        } catch (\Throwable $error) {
            db()->rollBack();
            if ($error instanceof \PDOException && in_array($error->getCode(), ['23000', '22001', '22007'], true)) {
                throw new Http(422, 'Data bertentangan dengan data yang ada atau kolom wajib belum lengkap.');
            }
            throw $error;
        }
    }

    private static function workflow(string $type, array &$data, ?array $previous, array $user): void
    {
        $flow = match ($type) {
            'finding' => ['draf', 'verifikasi', 'mitigasi', 'pemeriksaan_ulang', 'selesai'],
            'incident' => ['terbuka', 'mitigasi', 'verifikasi', 'selesai'],
            'report' => ['draf', 'diajukan', 'disetujui', 'arsip'],
        };
        $old = $previous['state'] ?? null;
        $state = $data['state'] ?? $old ?? $flow[0];
        $data['state'] = $state;
        if ($type === 'report' && $old === 'diajukan') {
            Auth::require($user, 'report.approve');
            if (!in_array($state, ['disetujui', 'draf'], true)) {
                throw new Http(422, 'Setujui laporan atau kembalikan ke draf sebelum mengubah isinya.');
            }
            if ($state === 'disetujui' && ($previous['user_id'] === null || (int) $previous['user_id'] === (int) $user['id'])) {
                throw new Http(422, 'Penyetuju harus berbeda dari pembuat laporan yang tercatat.');
            }
            $data = ['state' => $state];
            return;
        }
        if (($old === null && $state !== $flow[0]) || ($old !== null && $state !== $old && array_search($state, $flow, true) !== array_search($old, $flow, true) + 1)) {
            throw new Http(422, 'Gunakan urutan status yang ditetapkan.');
        }
        if ($type === 'report' && ($old === 'arsip' || ($old === 'disetujui' && $state === $old))) {
            throw new Http(422, 'Isi laporan yang telah disetujui tidak dapat diubah.');
        }
        if ($type === 'report' && $old === 'disetujui' && $state === 'arsip') {
            $data = ['state' => 'arsip'];
        }
        if (in_array($state, $type === 'report' ? ['disetujui', 'arsip'] : ['selesai'], true) || ($type === 'finding' && $state === 'mitigasi' && $state !== $old)) {
            Auth::require($user, $type === 'report' ? 'report.approve' : 'technical.approve');
        }
        if ($old === null && $type !== 'incident') {
            $data['user_id'] = (int) $user['id'];
        }
    }

    private static function reportRevision(?array $previous, int $userId): void
    {
        if ($previous === null || !in_array($previous['state'], ['disetujui', 'arsip'], true)) {
            throw new Http(422, 'Pilih laporan final untuk membuat revisi.');
        }
        $code = text_input($_POST, 'revision_code');
        $reason = text_input($_POST, 'revision_reason');
        if ($code === '' || $reason === '' || mb_strlen($code) > 100 || mb_strlen($reason) > 500
            || !mb_check_encoding($code . $reason, 'UTF-8')) {
            throw new Http(422, 'Isi nomor laporan baru dan alasan revisi yang valid.');
        }
        $data = array_intersect_key($previous, array_flip(['title','source','inspected_on','notes','evidence','mitigation']));
        self::put('reports', $data + [
            'code' => $code, 'state' => 'draf', 'user_id' => $userId,
            'revision_of' => $previous['id'], 'revision_reason' => $reason,
        ], 0);
        audit($userId, 'buat-revisi', 'reports');
    }

    private static function assign(string $type, int $id): void
    {
        $selected = $_POST['grants'] ?? [];
        if (!is_array($selected) || count($selected) > 100) {
            throw new Http(422, 'Pilihan hak akses tidak valid.');
        }
        $relation = $type === 'users' ? 'user_roles' : 'role_permissions';
        $owner = $type === 'users' ? 'user_id' : 'role_id';
        $column = $type === 'users' ? 'role_id' : 'permission_code';
        $allowed = $type === 'users' ? query('SELECT id FROM roles')->fetchAll(\PDO::FETCH_COLUMN) : query('SELECT code FROM permissions')->fetchAll(\PDO::FETCH_COLUMN);
        query("DELETE FROM $relation WHERE $owner = ?", [$id]);
        foreach ($selected as $grant) {
            if (!is_string($grant) || !in_array($grant, array_map('strval', $allowed), true)) {
                throw new Http(422, 'Role atau izin yang dipilih tidak dikenal.');
            }
            query("INSERT INTO $relation ($owner, $column) VALUES (?, ?)", [$id, $grant]);
        }
    }

    private static function import(string $table, array $fields): void
    {
        $file = $_FILES['csv'] ?? [];
        if (($file['error'] ?? null) !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name']) || $file['size'] > 1024 * 1024) {
            throw new Http(422, 'Pilih CSV dengan ukuran maksimal 1 MiB.');
        }
        $input = fopen($file['tmp_name'], 'rb');
        $header = fgetcsv($input, null, ',', '"', '');
        if ($header !== array_keys($fields)) {
            throw new Http(422, 'Gunakan tajuk kolom dari hasil ekspor CSV.');
        }
        $count = 0;
        while (($line = fgetcsv($input, null, ',', '"', '')) !== false) {
            if (count($line) !== count($header) || ++$count > 1000) {
                throw new Http(422, 'Format baris tidak valid atau melebihi 1000 baris.');
            }
            $inputRow = array_combine($header, $line);
            if (in_array(null, $inputRow, true)) {
                throw new Http(422, 'Baris CSV kosong.');
            }
            self::put($table, self::fields($fields, $inputRow), 0);
        }
        if ($count === 0) {
            throw new Http(422, 'CSV tidak berisi data.');
        }
    }
}
