<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;
use Sentinel\Services\Branding;
use Sentinel\Services\Reports;

final class IntelligenceReports
{
    public const TITLES = ['daily' => 'Daily Threat Intelligence', 'weekly' => 'Weekly Threat Intelligence', 'monthly' => 'Monthly Threat Intelligence',
        'url' => 'URL Intelligence', 'domain' => 'Domain Intelligence', 'ip' => 'IP Intelligence', 'malware' => 'Malware Intelligence',
        'vulnerability' => 'Vulnerability Intelligence', 'brand' => 'Institutional Domain Protection', 'healthcare' => 'Healthcare Cybersecurity Advisory',
        'asset' => 'Asset Vulnerability Assessment'];

    public static function create(string $kind, int $scanId, int $user): int
    {
        if (!isset(self::TITLES[$kind])) {
            throw new Http(422, 'Jenis laporan tidak valid.');
        }
        $today = date('Y-m-d');
        if ($scanId) {
            $scan = self::scan($scanId, $user);
            $results = [];
            foreach ($scan['matches'] as $entry) {
                $meta = $entry['metadata'];
                $results[] = ['title' => $meta['display_value'] ?? $meta['cve'], 'reference' => $meta['provider'] ?? 'Katalog CVE',
                    'status' => $meta['severity'] ?? 'unknown', 'inspected' => $meta['last_seen'] ?? $meta['published_at'] ?? $meta['retrieved_at'] ?? '—'];
            }
            $evidence = "Hasil pemeriksaan #" . $scanId . "\n" . $scan['display_value'] . "\nPrioritas " . $scan['priority'] . '/100';
        } else {
            $start = match ($kind) {
                'daily' => $today, 'weekly' => date('Y-m-d', strtotime('-6 days')), 'monthly' => date('Y-m-01'), default => '',
            };
            $results = self::aggregate($kind, $start, $today, $user);
            $evidence = $start ? 'Periode observasi: ' . $start . ' hingga ' . $today : 'Snapshot katalog pada ' . $today;
        }
        $snapshot = ['date' => $today, 'notes' => 'Ringkasan dari basis data Threat Intelligence internal.',
            'evidence' => $evidence,
            'mitigation' => 'Validasi sumber dan relevansi aset. Tinjau sumber resmi dan ikuti prosedur mitigasi institusi.',
            'method' => 'Pencocokan lokal dan analisis statis dengan aturan ' . Analysis::RULE . '.',
            'limits' => 'Katalog lokal dapat belum lengkap atau kedaluwarsa. Tidak ada kecocokan tidak membuktikan keamanan. Tabel memuat maksimal 50 entri.',
            'results' => $results];
        query('INSERT INTO ti_reports (code,title,kind,user_id,scan_id,snapshot) VALUES (?,?,?,?,?,?)',
            ['TI-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(5))), self::TITLES[$kind], $kind, $user, $scanId ?: null, Store::json($snapshot)]);
        $id = (int) db()->lastInsertId();
        audit($user, 'buat-laporan', 'threat');
        return $id;
    }

    private static function aggregate(string $kind, string $start, string $today, int $user): array
    {
        if ($kind === 'vulnerability') {
            return query('SELECT cve AS title,COALESCE(vendor,product) AS reference,severity AS status,published_at AS inspected
                FROM ti_vulnerabilities ORDER BY COALESCE(cvss,0) DESC,id DESC LIMIT 50')->fetchAll();
        }
        if ($kind === 'asset') {
            return query('SELECT CONCAT(a.code,\' / \',v.cve) AS title,av.basis AS reference,av.state AS status,av.updated_at AS inspected
                FROM ti_asset_vulnerabilities av JOIN institutional_assets a ON a.id=av.asset_id JOIN ti_vulnerabilities v ON v.id=av.vulnerability_id
                ORDER BY av.updated_at DESC LIMIT 50')->fetchAll();
        }
        if ($kind === 'healthcare') {
            return query("SELECT title,publisher AS reference,severity AS status,published_on AS inspected FROM ti_advisories WHERE healthcare=1 AND state<>'arsip' ORDER BY published_on DESC LIMIT 50")->fetchAll();
        }
        if ($kind === 'brand') {
            return query("SELECT display_value AS title,'Pemeriksaan kemiripan' AS reference,priority AS status,searched_at AS inspected
                FROM ti_scan_results WHERE user_id=? AND JSON_LENGTH(facts,'$.brand')>0 ORDER BY id DESC LIMIT 50", [$user])->fetchAll();
        }
        $filters = [];
        $args = [];
        if ($start !== '') {
            $filters[] = 's.retrieved_at>=? AND s.retrieved_at<TIMESTAMPADD(DAY,1,?)';
            array_push($args, $start, $today);
        }
        if (in_array($kind, ['url','domain'], true)) {
            $filters[] = 'i.kind=?';
            $args[] = $kind;
        } elseif ($kind === 'ip') {
            $filters[] = "i.kind IN ('ipv4','ipv6')";
        } elseif ($kind === 'malware') {
            $filters[] = "s.category='malware'";
        }
        $where = $filters ? 'WHERE ' . implode(' AND ', $filters) : '';
        return query("SELECT i.display_value AS title,p.title AS reference,s.severity AS status,COALESCE(s.last_seen,s.retrieved_at) AS inspected
            FROM ti_indicator_sources s JOIN ti_indicators i ON i.id=s.indicator_id JOIN ti_providers p ON p.id=s.provider_id $where
            ORDER BY s.retrieved_at DESC LIMIT 50", $args)->fetchAll();
    }

    public static function scan(int $id, int $user): array
    {
        $scan = query('SELECT id,kind,display_value,priority,rule_version,facts,searched_at FROM ti_scan_results WHERE id=? AND user_id=?', [$id,$user])->fetch();
        if (!$scan) {
            throw new Http(404, 'Pemeriksaan tidak ditemukan.');
        }
        $scan['facts'] = json_decode($scan['facts'], true, 64, JSON_THROW_ON_ERROR);
        $scan['matches'] = array_map(static fn ($json) => json_decode($json, true, 64, JSON_THROW_ON_ERROR),
            query('SELECT snapshot FROM ti_scan_matches WHERE scan_id=? ORDER BY position', [$id])->fetchAll(\PDO::FETCH_COLUMN));
        return $scan;
    }

    public static function document(int $id, int $user, bool $canApprove, bool $download): array
    {
        $record = self::record($id, $user, $canApprove);
        if (!$record) {
            throw new Http(404, 'Laporan intelijen tidak ditemukan.');
        }
        $document = $record['final_document'] === null
            ? self::liveDocument($record)
            : json_decode($record['final_document'], true, 64, JSON_THROW_ON_ERROR);
        if ($download) {
            Reports::download($document, $user, 'threat');
        }
        return $document;
    }

    public static function approve(int $id, int $user): void
    {
        Store::transaction(static function () use ($id, $user): void {
            if (!query('UPDATE ti_reports SET approved_at=NOW(),approver_id=? WHERE id=? AND approved_at IS NULL AND user_id<>?',
                [$user,$id,$user])->rowCount()) {
                throw new Http(422, 'Penyetuju harus berbeda dari pembuat laporan yang tercatat.');
            }
            self::freeze($id, $user);
        });
    }

    public static function backfillFinalDocuments(): void
    {
        while ($id = query('SELECT id FROM ti_reports WHERE approved_at IS NOT NULL AND final_document IS NULL ORDER BY id LIMIT 1')->fetchColumn()) {
            self::freeze((int) $id, 0, true);
        }
    }

    private static function record(int $id, int $user, bool $canApprove): array|false
    {
        return query('SELECT t.*,u.title AS officer,a.title AS approver FROM ti_reports t LEFT JOIN users u ON u.id=t.user_id
            LEFT JOIN users a ON a.id=t.approver_id WHERE t.id=? AND (t.approved_at IS NOT NULL OR t.user_id=? OR ?=1)', [$id, $user, (int) $canApprove])->fetch();
    }

    private static function freeze(int $id, int $user, bool $legacy = false): void
    {
        $document = self::liveDocument(self::record($id, $user, true));
        $document['report']['legacy_snapshot'] = $legacy;
        query('UPDATE ti_reports SET final_document=? WHERE id=? AND final_document IS NULL', [Store::json($document), $id]);
    }

    private static function liveDocument(array $record): array
    {
        $snapshot = json_decode($record['snapshot'], true, 64, JSON_THROW_ON_ERROR);
        $report = ['id' => $record['id'], 'title' => $record['title'], 'code' => $record['code'], 'source' => $record['kind'],
            'inspected_on' => $snapshot['date'], 'officer' => $record['officer'], 'state' => $record['approved_at'] ? 'disetujui' : 'draf',
            'notes' => $snapshot['notes'] . "\n" . $snapshot['method'] . "\n" . $snapshot['limits'], 'evidence' => $snapshot['evidence'], 'mitigation' => $snapshot['mitigation']];
        $institution = query("SELECT value FROM system_settings WHERE title='institution_name'")->fetchColumn() ?: 'Pusat Kesehatan TNI Angkatan Udara';
        $logo = Branding::dataUri();
        $signatures = $record['approved_at'] ? [['title' => $record['approver'], 'created_at' => $record['approved_at']]] : [];
        $results = $snapshot['results'];
        return compact('report', 'institution', 'logo', 'signatures', 'results');
    }
}
