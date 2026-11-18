<?php
declare(strict_types=1);
namespace Sentinel\Controllers;

use Sentinel\Core\Auth;
use Sentinel\Core\Http;

final class Dashboard
{
    public static function data(array $user): array
    {
        Auth::require($user, 'dashboard.read');
        $from = text_input($_GET, 'from');
        $to = text_input($_GET, 'to');
        $month = text_input($_GET, 'month');
        $year = text_input($_GET, 'year');
        $period = text_input($_GET, 'period');
        $periods = query('SELECT id,title,starts_on,ends_on FROM activity_periods ORDER BY starts_on DESC')->fetchAll();
        $selected = null;
        foreach ($periods as $entry) {
            if ((string) $entry['id'] === $period) {
                $selected = $entry;
            }
        }
        foreach ([$from, $to] as $date) {
            if ($date !== '' && !self::date($date)) {
                throw new Http(422, 'Tanggal filter tidak valid.');
            }
        }
        if (($month !== '' && !preg_match('/^\d{4}-(0[1-9]|1[0-2])$/D', $month))
            || ($year !== '' && !preg_match('/^\d{4}$/D', $year)) || ($period !== '' && $selected === null)) {
            throw new Http(422, 'Filter periode tidak valid.');
        }
        $start = max($from ?: '1000-01-01', $month ? $month . '-01' : '1000-01-01', $year ? $year . '-01-01' : '1000-01-01', $selected['starts_on'] ?? '1000-01-01');
        $end = min($to ?: '9999-12-31', $month ? date('Y-m-t', strtotime($month . '-01')) : '9999-12-31', $year ? $year . '-12-31' : '9999-12-31', $selected['ends_on'] ?? '9999-12-31');
        $periodFilters = $selected === null ? [] : [
            'activities' => [' AND period_id = ?', [$selected['id']]],
            'inspection_schedules' => [' AND activity_id IN (SELECT id FROM activities WHERE period_id = ?)', [$selected['id']]],
        ];
        $cards = [];
        foreach ([
            ['Total kegiatan', 'activities', 'held_on', null],
            ['Pemeriksaan teknis', 'inspection_schedules', 'scheduled_on', null],
            ['Pemeriksaan selesai', 'inspection_schedules', 'scheduled_on', "state = 'selesai'"],
            ['Pemeriksaan tertunda', 'inspection_schedules', 'scheduled_on', "state = 'tertunda'"],
            ['Temuan keamanan', 'security_findings', 'inspected_on', null],
            ['Insiden aktif', 'security_incidents', 'created_at', "state <> 'selesai'"],
            ['Laporan', 'reports', 'created_at', Auth::allows($user, 'report.read') ? null : "state = 'disetujui'"],
            ['Aset institusi', 'institutional_assets', 'created_at', null],
        ] as [$label, $table, $column, $condition]) {
            $where = "DATE(COALESCE($column, created_at)) BETWEEN ? AND ?";
            if ($condition !== null) {
                $where .= ' AND ' . $condition;
            }
            [$extra, $values] = $periodFilters[$table] ?? ['', []];
            $cards[$label] = (int) query("SELECT COUNT(*) FROM $table WHERE $where$extra", [$start, $end, ...$values])->fetchColumn();
        }
        $charts = [];
        foreach ([
            ['Pemeriksaan harian', 'inspection_schedules', 'scheduled_on', 'scheduled_on', 31],
            ['Pemeriksaan bulanan', 'inspection_schedules', "DATE_FORMAT(scheduled_on, '%Y-%m')", 'scheduled_on', 12],
            ['Jenis temuan', 'security_findings', 'category', 'inspected_on', 12],
            ['Keparahan insiden', 'security_incidents', 'severity', 'created_at', 5],
            ['Penyelesaian insiden', 'security_incidents', 'state', 'created_at', 5],
        ] as [$label, $table, $key, $column, $limit]) {
            [$extra, $values] = $periodFilters[$table] ?? ['', []];
            $charts[$label] = query("SELECT $key AS label,COUNT(*) AS total FROM $table WHERE $key IS NOT NULL AND DATE($column) BETWEEN ? AND ?$extra GROUP BY $key ORDER BY $key DESC LIMIT $limit",
                [$start, $end, ...$values])->fetchAll();
        }
        [$extra, $values] = $periodFilters['inspection_schedules'] ?? ['', []];
        $schedule = Auth::allows($user, 'admin.read') ? query("SELECT title,scheduled_on,state FROM inspection_schedules WHERE scheduled_on >= CURDATE() AND scheduled_on BETWEEN ? AND ?$extra ORDER BY scheduled_on LIMIT 5", [$start, $end, ...$values])->fetchAll() : [];
        $events = Auth::allows($user, 'audit.read') ? query('SELECT action,module,created_at FROM audit_logs ORDER BY id DESC LIMIT 5')->fetchAll() : [];
        return compact('cards', 'charts', 'schedule', 'events', 'periods', 'from', 'to', 'month', 'year', 'period');
    }

    private static function date(string $value): bool
    {
        return preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $value, $parts)
            && checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1]);
    }
}
