<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;

final class Catalog
{
    public static function id(array $input, string $field, bool $optional = false): int
    {
        $value = $input[$field] ?? null;
        if ($optional && ($value === null || $value === '')) {
            return 0;
        }
        if (!(is_int($value) || is_string($value)) || !preg_match('/^[1-9][0-9]{0,17}$/D', (string) $value)) {
            throw new Http(422, 'ID tidak valid.');
        }
        return (int) $value;
    }

    public static function indicators(array $input, int $limit = 25, string $category = ''): array
    {
        $after = self::id($input, 'after', true);
        $where = ['1=1'];
        $params = [];
        $kind = text_input($input, 'kind');
        $source = text_input($input, 'source');
        $state = text_input($input, 'state');
        $severity = text_input($input, 'severity');
        $search = Store::text($input['q'] ?? null, 200);
        foreach ([
            [$kind, 'i.kind=?'], [$source, 'p.code=?'], [$category, 's.category=?'], [$severity, 's.severity=?'],
        ] as [$value, $condition]) {
            if ($value !== '') {
                $where[] = $condition;
                $params[] = $value;
            }
        }
        if ($state === 'active' || $state === 'expired') {
            $where[] = $state === 'active' ? '(s.expires_at IS NULL OR s.expires_at>NOW())' : 's.expires_at<=NOW()';
        }
        if ($search !== null) {
            $pattern = '%' . $search . '%';
            $where[] = '(i.display_value LIKE ? OR i.host LIKE ? OR s.malware_family LIKE ?)';
            array_push($params, $pattern, $pattern, $pattern);
        }
        self::range($input, 's.retrieved_at', $where, $params);
        $filter = implode(' AND ', $where);
        $candidateFilter = str_replace('i.', 'c.', $filter);
        // Bound grouping to one keyset page, and then project matching observations.
        $candidates = "SELECT c.id FROM ti_indicators c FORCE INDEX (PRIMARY) WHERE c.id>? AND (
            SELECT 1 FROM ti_indicator_sources s JOIN ti_providers p ON p.id=s.provider_id
            WHERE s.indicator_id=c.id AND $candidateFilter LIMIT 1)=1 ORDER BY c.id LIMIT $limit";
        return query("SELECT i.id,i.kind,i.display_value,GROUP_CONCAT(DISTINCT p.title ORDER BY p.title SEPARATOR ', ') AS provider,
            GROUP_CONCAT(DISTINCT s.category ORDER BY s.category SEPARATOR ', ') AS category,
            GROUP_CONCAT(DISTINCT s.malware_family ORDER BY s.malware_family SEPARATOR ', ') AS family,
            MAX(s.last_seen) AS last_seen,MAX(s.retrieved_at) AS retrieved_at
            FROM ($candidates) page JOIN ti_indicators i ON i.id=page.id
            JOIN ti_indicator_sources s ON s.indicator_id=i.id JOIN ti_providers p ON p.id=s.provider_id
            WHERE $filter GROUP BY i.id,i.kind,i.display_value ORDER BY i.id", [$after,...$params,...$params])->fetchAll();
    }

    public static function indicator(int $id): array
    {
        $entry = query('SELECT id,kind,display_value,ip_scope FROM ti_indicators WHERE id=?', [$id])->fetch();
        if (!$entry) {
            throw new Http(404, 'Indikator tidak ditemukan.');
        }
        $entry['sources'] = query('SELECT p.id AS provider_id,p.title AS provider,s.category,s.severity,s.confidence,s.malware_family,s.first_seen,s.last_seen,s.expires_at,
            s.verified_at,s.reference_text,s.evidence,s.evidence_sha256,s.parser_version,s.retrieved_at FROM ti_indicator_sources s
            JOIN ti_providers p ON p.id=s.provider_id WHERE indicator_id=? ORDER BY p.id', [$id])->fetchAll();
        return $entry;
    }

    public static function vulnerabilities(array $input, int $limit = 25): array
    {
        $where = ['id > ?'];
        $args = [self::id($input, 'after', true)];
        $search = Store::text($input['q'] ?? null, 140);
        if ($search !== null) {
            $where[] = '(cve LIKE ? OR vendor LIKE ? OR product LIKE ?)';
            array_push($args, ...array_fill(0, 3, '%' . $search . '%'));
        }
        $severity = text_input($input, 'severity');
        if ($severity !== '') {
            $where[] = 'severity=?';
            $args[] = $severity;
        }
        if (text_input($input, 'state') === 'kev') {
            $where[] = 'kev_added_on IS NOT NULL';
        }
        self::range($input, 'published_at', $where, $args);
        $filter = implode(' AND ', $where);
        return query("SELECT id,cve,vendor,product,cvss,severity,epss,epss_on,kev_added_on,kev_due_on,published_at
            FROM ti_vulnerabilities WHERE $filter ORDER BY id LIMIT $limit", $args)->fetchAll();
    }

    public static function advisories(array $input, int $limit = 25): array
    {
        $where = ['id > ?'];
        $args = [self::id($input, 'after', true)];
        $q = Store::text($input['q'] ?? null, 140);
        if ($q !== null) {
            $where[] = '(title LIKE ? OR publisher LIKE ? OR product LIKE ? OR cve LIKE ?)';
            array_push($args, ...array_fill(0, 4, '%' . $q . '%'));
        }
        foreach (['severity','state','category'] as $field) {
            $value = text_input($input, $field);
            if ($value !== '') {
                $where[] = "$field=?";
                $args[] = $value;
            }
        }
        if (text_input($input, 'sector') === 'healthcare') {
            $where[] = 'healthcare=1';
        }
        self::range($input, 'published_on', $where, $args);
        $filter = implode(' AND ', $where);
        return query("SELECT id,title,publisher,published_on,severity,cve,state,healthcare FROM ti_advisories WHERE $filter ORDER BY id LIMIT $limit", $args)->fetchAll();
    }

    public static function alerts(array $input, int $limit = 25): array
    {
        $where = ['id > ?'];
        $args = [self::id($input, 'after', true)];
        foreach (['severity','status'] as $field) {
            $value = text_input($input, $field);
            if ($value !== '') {
                $where[] = "$field=?";
                $args[] = $value;
            }
        }
        $filter = implode(' AND ', $where);
        return query("SELECT id,title,category,severity,status,assignee_id,created_at,last_seen,route FROM ti_alerts WHERE $filter ORDER BY id LIMIT $limit", $args)->fetchAll();
    }

    public static function summary(array $input): array
    {
        $conditions = ['1=1'];
        $params = [];
        foreach (['kind' => 'i.kind', 'source' => 'p.code', 'severity' => 's.severity'] as $parameter => $column) {
            $value = text_input($input, $parameter);
            if ($value !== '') {
                $conditions[] = "$column=?";
                $params[] = $value;
            }
        }
        if (in_array(text_input($input, 'state'), ['active','expired'], true)) {
            $conditions[] = text_input($input, 'state') === 'active' ? '(s.expires_at IS NULL OR s.expires_at>NOW())' : 's.expires_at<=NOW()';
        }
        self::range($input, 's.retrieved_at', $conditions, $params);
        $filter = implode(' AND ', $conditions);
        $base = "FROM ti_indicator_sources s JOIN ti_indicators i ON i.id=s.indicator_id JOIN ti_providers p ON p.id=s.provider_id WHERE $filter";
        $types = query("SELECT i.kind AS label,COUNT(DISTINCT i.id) AS total $base GROUP BY i.kind ORDER BY i.kind", $params)->fetchAll();
        $counts = array_column($types, 'total', 'label');
        $critical = (int) query("SELECT COUNT(DISTINCT CASE WHEN s.severity='critical' THEN i.id END) $base", $params)->fetchColumn();
        $cards = [
            'Total indikator' => array_sum($counts), 'URL dilaporkan' => (int) ($counts['url'] ?? 0),
            'Domain dilaporkan' => (int) ($counts['domain'] ?? 0), 'IP dilaporkan' => ($counts['ipv4'] ?? 0) + ($counts['ipv6'] ?? 0),
            'Hash dilaporkan' => ($counts['sha256'] ?? 0) + ($counts['sha1'] ?? 0) + ($counts['md5'] ?? 0),
            'Indikator kritis' => $critical,
        ];
        $global = [];
        foreach ([
            'Kerentanan katalog' => 'ti_vulnerabilities', 'Advisori' => 'ti_advisories', 'Provider aktif' => 'ti_providers WHERE enabled=1',
            'Sinkronisasi berhasil' => "ti_sync_jobs WHERE state='succeeded' AND action='sync'",
            'Sinkronisasi gagal' => "ti_sync_jobs WHERE state='failed' AND action='sync'",
            'Temuan baru (7 hari)' => "ti_scan_results WHERE searched_at>=NOW()-INTERVAL 7 DAY AND EXISTS (SELECT 1 FROM ti_scan_matches WHERE scan_id=ti_scan_results.id)",
            'Aset perlu tinjauan' => "ti_asset_vulnerabilities WHERE state IN ('potensial','terkonfirmasi')",
        ] as $label => $table) {
            $target = $label === 'Aset perlu tinjauan' ? 'DISTINCT asset_id' : '*';
            $global[$label] = (int) query("SELECT COUNT($target) FROM $table")->fetchColumn();
        }
        $charts = ['Jenis indikator' => $types];
        foreach ([
            'Keparahan observasi' => 's.severity', 'Keluarga malware' => "COALESCE(s.malware_family,'Tidak diketahui')",
            'Tren observasi harian' => 'DATE(s.retrieved_at)', 'Kontribusi sumber' => 'p.title',
        ] as $label => $column) {
            $charts[$label] = query("SELECT $column AS label,COUNT(*) AS total $base GROUP BY $column ORDER BY "
                . ($label === 'Tren observasi harian' ? 'label DESC' : 'total DESC') . ' LIMIT 14', $params)->fetchAll();
        }
        $charts['Kerentanan bulanan'] = query("SELECT DATE_FORMAT(published_at,'%Y-%m') AS label,COUNT(*) AS total FROM ti_vulnerabilities WHERE published_at IS NOT NULL GROUP BY label ORDER BY label DESC LIMIT 12")->fetchAll();
        $charts['Job sinkronisasi'] = query("SELECT state AS label,COUNT(*) AS total FROM ti_sync_jobs GROUP BY state ORDER BY state")->fetchAll();
        $charts['Mitigasi aset'] = query("SELECT state AS label,COUNT(*) AS total FROM ti_asset_vulnerabilities GROUP BY state ORDER BY state")->fetchAll();
        $freshness = query('SELECT MAX(last_success_at) FROM ti_providers')->fetchColumn();
        return compact('cards','global','charts','freshness');
    }

    private static function range(array $input, string $column, array &$conditions, array &$params): void
    {
        $from = text_input($input, 'from');
        $to = text_input($input, 'to');
        if (($from !== '' && Store::date($from) !== $from) || ($to !== '' && Store::date($to) !== $to) || ($from && $to && $from > $to)) {
            throw new Http(422, 'Rentang tanggal tidak valid.');
        }
        if ($from !== '') {
            $conditions[] = "$column>=?";
            $params[] = $from;
        }
        if ($to !== '') {
            $conditions[] = "$column<TIMESTAMPADD(DAY,1,?)";
            $params[] = $to;
        }
    }
}
