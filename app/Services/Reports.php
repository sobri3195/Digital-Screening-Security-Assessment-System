<?php
declare(strict_types=1);
namespace Sentinel\Services;

use Dompdf\Dompdf;
use Dompdf\Options;
use Sentinel\Core\Auth;
use Sentinel\Core\Http;

final class Reports
{
    public static function results(array $report): array
    {
        $sources = [
            'kegiatan' => ['activities', 'held_on', 'code', 'state'],
            'url' => ['url_inspections', 'created_at', 'host', null],
            'file' => ['file_inspections', 'created_at', 'mime', 'scan_status'],
            'aset' => ['institutional_assets', 'inspected_on', 'code', 'patch_state'],
            'temuan' => ['security_findings', 'inspected_on', 'category', 'severity'],
            'insiden' => ['security_incidents', 'created_at', 'category', 'severity'],
        ];
        $source = $report['source'] ?? '';
        $date = $report['inspected_on'] ?? date('Y-m-d');
        if (isset($sources[$source])) {
            [$table, $column, $reference, $state] = $sources[$source];
            $status = $state ?? 'NULL';
            return query("SELECT title,$reference AS reference,$status AS status,DATE(COALESCE($column,created_at)) AS inspected
                FROM $table WHERE DATE(COALESCE($column,created_at)) = ? ORDER BY id DESC LIMIT 50", [$date])->fetchAll();
        }
        if (!in_array($source, ['bulanan', 'tahunan', 'rekapitulasi'], true)) {
            return [];
        }
        $start = match ($source) {
            'bulanan' => substr($date, 0, 7) . '-01',
            'tahunan' => substr($date, 0, 4) . '-01-01',
            default => '1000-01-01',
        };
        $end = match ($source) {
            'bulanan' => date('Y-m-t', strtotime($date)),
            'tahunan' => substr($date, 0, 4) . '-12-31',
            default => $date,
        };
        $results = [];
        foreach ($sources as $label => [$table, $column]) {
            $count = query("SELECT COUNT(*) FROM $table WHERE DATE(COALESCE($column,created_at)) BETWEEN ? AND ?", [$start, $end])->fetchColumn();
            $results[] = ['title' => ucfirst($label), 'reference' => (string) $count, 'status' => $start, 'inspected' => $end];
        }
        return $results;
    }

    public static function document(int $id, array $user, bool $download): array
    {
        if (!Auth::allows($user, 'report.read')) {
            Auth::require($user, 'report.approved');
            $rule = " AND r.state = 'disetujui'";
        } else {
            $rule = '';
        }
        $report = query("SELECT r.*,u.title AS officer FROM reports r LEFT JOIN users u ON u.id=r.user_id WHERE r.id = ?$rule", [$id])->fetch();
        if (!$report) {
            throw new Http(404, 'Laporan tidak ditemukan.');
        }
        $signatures = query('SELECT u.title,a.created_at FROM report_approvals a JOIN users u ON u.id=a.user_id WHERE a.report_id = ? ORDER BY a.id', [$id])->fetchAll();
        $institution = query("SELECT value FROM system_settings WHERE title = 'institution_name'")->fetchColumn() ?: 'Pusat Kesehatan TNI Angkatan Udara';
        $logo = Branding::dataUri();
        $results = isset($report['result_snapshot']) ? json_decode($report['result_snapshot'], true, 512, JSON_THROW_ON_ERROR)
            : (in_array($report['state'], ['disetujui', 'arsip'], true) ? [] : self::results($report));
        if ($download) {
            self::download(compact('report','institution','signatures','logo','results'), (int) $user['id']);
        }
        return compact('report', 'institution', 'signatures', 'logo', 'results');
    }

    public static function download(array $document, int $userId, string $module = 'reports'): never
    {
        ['report' => $report, 'institution' => $institution, 'signatures' => $signatures, 'logo' => $logo, 'results' => $results] = $document;
        $download = true;
        if (!class_exists(Dompdf::class)) {
            throw new Http(503, 'Generator PDF belum terpasang. Jalankan Composer sesuai petunjuk instalasi.');
        }
        $options = new Options(['isRemoteEnabled' => false, 'isPhpEnabled' => false, 'isJavascriptEnabled' => false, 'chroot' => BASE . '/public']);
        $pdf = new Dompdf($options);
        $pdf->setPaper('A4');
        ob_start();
        require BASE . '/app/Views/document.php';
        $pdf->loadHtml((string) ob_get_clean(), 'UTF-8');
        $pdf->render();
        $pdf->getCanvas()->page_text(475, 795, 'Halaman {PAGE_NUM} / {PAGE_COUNT}', 'Helvetica', 9, [0.2, 0.2, 0.2]);
        audit($userId, 'download', $module);
        $filename = $module === 'reports' ? 'laporan-' : 'laporan-intelijen-';
        $pdf->stream($filename . $report['id'] . '.pdf');
        exit;
    }
}
