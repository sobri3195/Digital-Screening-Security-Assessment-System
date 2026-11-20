<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

final class Feeds
{
    public const AUTOMATED = ['cisa','nvd','epss','urlhaus','threatfox','malwarebazaar'];
    private const CISA = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
    private const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    private const EPSS = 'https://api.first.org/data/v1/epss';

    public static function configured(string $provider): bool
    {
        $settings = (require BASE . '/config/threat.php')['providers'];
        $name = $settings[$provider][2] ?? null;
        return $name === null || self::key($name) !== '';
    }

    private static function key(string $name): string
    {
        $value = config($name);
        return $value !== '' && preg_match('/^[\x21-\x7e]{1,512}$/D', $value) ? $value : '';
    }

    public static function pull(string $code, array $checkpoint, bool $preview = false, ?callable $fetch = null): array
    {
        $fetch ??= FeedHttp::request(...);
        $next = null;
        $watermark = null;
        if (!in_array($code, self::AUTOMATED, true) || !self::configured($code)) {
            throw new FeedFailure('Adapter otomatis atau kredensial feed belum dikonfigurasi.');
        }
        switch ($code) {
            case 'cisa':
                $json = $fetch(self::CISA, [], null);
                break;
            case 'nvd':
                [$json,$next,$watermark] = self::nvdPage($checkpoint, $preview, $fetch);
                break;
            case 'epss':
                $limit = $preview ? 5 : 75;
                $cutoff = (int) ($checkpoint['cutoff'] ?? query('SELECT COALESCE(MAX(id),0) FROM ti_vulnerabilities WHERE nvd_retrieved_at IS NOT NULL OR kev_retrieved_at IS NOT NULL')->fetchColumn());
                $cvEs = query("SELECT id,cve FROM ti_vulnerabilities WHERE id>? AND id<=? AND (nvd_retrieved_at IS NOT NULL OR kev_retrieved_at IS NOT NULL) ORDER BY id LIMIT $limit", [(int) ($checkpoint['offset'] ?? 0), $cutoff])->fetchAll();
                if (!$cvEs) {
                    return ['rows' => [], 'rejected' => 0, 'next' => null, 'watermark' => null, 'message' => 'Belum ada CVE rujukan dari CISA atau NVD.'];
                }
                $allowed = array_column($cvEs, 'cve');
                $endpoint = self::EPSS . '?' . http_build_query(['cve' => implode(',', $allowed)], '', '&', PHP_QUERY_RFC3986);
                $json = $fetch($endpoint, [], null);
                if (isset($json['data']) && is_array($json['data'])) {
                    $json['data'] = array_values(array_filter($json['data'], static fn ($row) => is_array($row) && in_array($row['cve'] ?? '', $allowed, true)));
                }
                if (count($cvEs) === $limit && (int) end($cvEs)['id'] < $cutoff) {
                    $next = ['cutoff' => $cutoff, 'offset' => (int) end($cvEs)['id']];
                }
                break;
            case 'urlhaus':
                $json = $fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', ['Auth-Key: ' . self::key('TI_URLHAUS_KEY')], null);
                break;
            case 'threatfox':
                $json = $fetch('https://threatfox-api.abuse.ch/api/v1/', ['Auth-Key: ' . self::key('TI_THREATFOX_KEY'), 'Content-Type: application/json'],
                    '{"query":"get_iocs","days":1}');
                break;
            case 'malwarebazaar':
                $json = $fetch('https://mb-api.abuse.ch/api/v1/', ['Auth-Key: ' . self::key('TI_MALWAREBAZAAR_KEY'), 'Content-Type: application/x-www-form-urlencoded'],
                    'query=get_recent&selector=100');
                break;
        }
        [$rows, $rejected] = self::parse($code, $json);
        if ($code === 'cisa' && !$preview) {
            $released = Store::date($json['dateReleased'] ?? null, true);
            if ($released === null || $rejected !== 0 || !$rows || ($json['count'] ?? null) !== count($rows)
                || count(array_unique(array_column($rows, 'cve'))) !== count($rows)) {
                throw new FeedFailure('Snapshot CISA KEV tidak lengkap atau berisi entri duplikat.');
            }
            if ($released < ($checkpoint['released'] ?? '')) {
                throw new FeedFailure('Snapshot CISA KEV lebih lama dari sinkronisasi terakhir.');
            }
            $watermark = ['released' => $released];
        }
        if ($preview) {
            $rows = array_slice($rows, 0, 5);
            $next = null;
        }
        return ['rows' => $rows, 'rejected' => $rejected, 'next' => $next, 'watermark' => $watermark, 'message' => 'Respons feed tervalidasi.'];
    }

    private static function nvdPage(array $checkpoint, bool $preview, callable $fetch): array
    {
        $historical = isset($checkpoint['history_end']);
        if ($historical) {
            $start = $checkpoint['history_start'];
            $end = min($start + 119 * 86400 - 1, $checkpoint['history_end']);
            $parameters = ['pubStartDate'=>gmdate('Y-m-d\TH:i:s.000\Z',$start), 'pubEndDate'=>gmdate('Y-m-d\TH:i:s.999\Z',$end)];
        } else {
            $windowEnd = $checkpoint['end'] ?? gmdate('Y-m-d\TH:i:s.000\Z');
            $minimum = gmdate('Y-m-d\TH:i:s.000\Z', time() - 119 * 86400);
            $windowStart = min($windowEnd, $checkpoint['start'] ?? max($minimum,
                $checkpoint['watermark'] ?? gmdate('Y-m-d\TH:i:s.000\Z', time() - 7 * 86400)));
            $parameters = ['lastModStartDate'=>$windowStart, 'lastModEndDate'=>$windowEnd];
        }
        $offset = (int) ($checkpoint['offset'] ?? 0);
        $parameters += ['startIndex'=>$offset, 'resultsPerPage'=>$preview ? 5 : 100];
        $key = self::key('TI_NVD_KEY');
        $json = $fetch(self::NVD . '?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986), $key ? ['apiKey: ' . $key] : [], null);
        $pageCount = is_array($json['vulnerabilities'] ?? null) ? count($json['vulnerabilities']) : 0;
        $total = filter_var($json['totalResults'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);
        if ($total === false || (int) ($json['startIndex'] ?? -1) !== $offset || ($pageCount === 0 && $offset < $total)) {
            throw new FeedFailure('Paginasi NVD tidak valid.', true);
        }
        if ($offset + $pageCount < $total) {
            $cursor = $historical ? $checkpoint : ['start'=>$windowStart,'end'=>$windowEnd];
            $cursor['offset'] = $offset + $pageCount;
            return [$json,$cursor,null];
        }
        if ($historical) {
            if ($end >= $checkpoint['history_end']) {
                return [$json,null,null];
            }
            unset($checkpoint['offset']);
            $checkpoint['history_start'] = $end + 1;
            return [$json,$checkpoint,null];
        }
        return [$json,null,['watermark'=>gmdate('Y-m-d\TH:i:s.000\Z', strtotime($windowEnd) - 60)]];
    }

    public static function parse(string $code, array $json): array
    {
        $key = match ($code) {
            'cisa','nvd' => 'vulnerabilities',
            'urlhaus' => 'urls',
            'epss','threatfox','malwarebazaar' => 'data',
            default => throw new FeedFailure('Parser feed tidak terdaftar.'),
        };
        if (in_array($code, ['urlhaus','threatfox','malwarebazaar'], true)) {
            $status = $json['query_status'] ?? null;
            if ($status === 'no_result' || $status === 'no_results') {
                return [[], 0];
            }
            if ($status !== 'ok') {
                throw new FeedFailure('Feed menolak permintaan. Periksa kredensial dan akses institusional.');
            }
        }
        $records = $json[$key] ?? null;
        if (!is_array($records) || !array_is_list($records) || count($records) > 30000) {
            throw new FeedFailure('Daftar feed tidak valid atau terlalu besar.');
        }
        $rows = [];
        $rejected = 0;
        foreach ($records as $record) {
            if (!is_array($record)) {
                $rejected++;
                continue;
            }
            try {
                $normalized = match ($code) {
                    'cisa' => [self::kev($record)],
                    'nvd' => [self::nvd($record)],
                    'epss' => [self::epss($record)],
                    'urlhaus','threatfox','malwarebazaar' => self::observations($code, $record),
                };
                if (!$normalized) {
                    $rejected++;
                }
                array_push($rows, ...$normalized);
            } catch (\Sentinel\Core\Http) {
                $rejected++;
            }
        }
        if (!$rows && $rejected > 0) {
            throw new FeedFailure('Seluruh entri ditolak oleh parser.');
        }
        return [$rows, $rejected];
    }

    private static function cve(mixed $id): string
    {
        if (!is_string($id) || !preg_match('/^CVE-[0-9]{4}-[0-9]{4,19}$/D', $id)) {
            throw new \Sentinel\Core\Http(422, 'CVE tidak valid.');
        }
        return $id;
    }

    private static function kev(array $row): array
    {
        $added = Store::date($row['dateAdded'] ?? null);
        if ($added === null) {
            throw new \Sentinel\Core\Http(422, 'Tanggal CISA tidak valid.');
        }
        return ['cve' => self::cve($row['cveID'] ?? null), 'vendor' => Store::text($row['vendorProject'] ?? null, 140),
            'product' => Store::text($row['product'] ?? null, 140), 'title' => Store::text($row['vulnerabilityName'] ?? null, 255),
            'added' => $added, 'description' => Store::text($row['shortDescription'] ?? null, 8000),
            'action' => Store::text($row['requiredAction'] ?? null, 8000), 'due' => Store::date($row['dueDate'] ?? null),
            'ransomware' => Store::text($row['knownRansomwareCampaignUse'] ?? null, 60),
            'notes' => Store::text($row['notes'] ?? null, 3000), 'parser' => 'cisa-1',
            'reference' => 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'];
    }

    private static function nvd(array $record): array
    {
        $row = is_array($record['cve'] ?? null) ? $record['cve'] : [];
        $description = null;
        foreach ($row['descriptions'] ?? [] as $variant) {
            if (($variant['lang'] ?? null) === 'en') {
                $description = Store::text($variant['value'] ?? null, 8000);
                break;
            }
        }
        $metric = [];
        foreach (['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'] as $name) {
            $metrics = $row['metrics'][$name] ?? [];
            foreach ($metrics as $entry) {
                $metric = $entry['cvssData'] ?? [];
                if (!isset($metric['baseSeverity'])) {
                    $metric['baseSeverity'] = $entry['baseSeverity'] ?? '';
                }
                if (($entry['type'] ?? '') === 'Primary') {
                    break;
                }
            }
            if ($metric) {
                break;
            }
        }
        $score = $metric['baseScore'] ?? null;
        $severity = strtolower((string) ($metric['baseSeverity'] ?? ''));
        $products = [];
        foreach ($row['configurations'] ?? [] as $group) {
            foreach ($group['nodes'] ?? [] as $node) {
                if (!empty($node['negate'])) {
                    continue;
                }
                foreach ($node['cpeMatch'] ?? [] as $entry) {
                    if (($entry['vulnerable'] ?? false) !== true || count($products) >= 100
                        || !preg_match('~^cpe:2\.3:[aoh]:([^:\\\\]{1,140}):([^:\\\\]{1,140}):([^:\\\\]{1,100}):~D', $entry['criteria'] ?? '', $parts)) {
                        continue;
                    }
                    $products[] = ['vendor' => $parts[1], 'product' => $parts[2], 'version' => $parts[3],
                        'cpe' => Store::text($entry['criteria'], 255),
                        'start_including' => Store::text($entry['versionStartIncluding'] ?? null, 100),
                        'start_excluding' => Store::text($entry['versionStartExcluding'] ?? null, 100),
                        'end_including' => Store::text($entry['versionEndIncluding'] ?? null, 100),
                        'end_excluding' => Store::text($entry['versionEndExcluding'] ?? null, 100)];
                }
            }
        }
        $refs = array_values(array_filter(array_map(static fn ($entry) => Indicator::reference($entry['url'] ?? null), array_slice(is_array($row['references'] ?? null) ? $row['references'] : [], 0, 12))));
        $weaknesses = [];
        foreach ($row['weaknesses'] ?? [] as $entry) {
            foreach ($entry['description'] ?? [] as $one) {
                if (preg_match('/^CWE-[0-9]{1,6}$/D', $one['value'] ?? '')) {
                    $weaknesses[$one['value']] = true;
                }
            }
        }
        return ['cve' => self::cve($row['id'] ?? null), 'vendor' => $products[0]['vendor'] ?? null, 'product' => $products[0]['product'] ?? null,
            'description' => $description, 'cvss' => is_numeric($score) && $score >= 0 && $score <= 10 ? $score : null,
            'vector' => Store::text($metric['vectorString'] ?? null, 255), 'severity' => in_array($severity, Store::SEVERITIES, true) ? $severity : null,
            'published' => Store::date($row['published'] ?? null, true), 'modified' => Store::date($row['lastModified'] ?? null, true),
            'products' => $products, 'references' => $refs, 'weaknesses' => array_keys($weaknesses), 'parser' => 'nvd-1'];
    }

    private static function epss(array $row): array
    {
        $date = Store::date($row['date'] ?? null);
        if (!$date || !is_numeric($row['epss'] ?? null) || !is_numeric($row['percentile'] ?? null)
            || $row['epss'] < 0 || $row['epss'] > 1 || $row['percentile'] < 0 || $row['percentile'] > 1) {
            throw new \Sentinel\Core\Http(422, 'Baris EPSS tidak valid.');
        }
        return ['cve' => self::cve($row['cve'] ?? null), 'epss' => round((float) $row['epss'], 8), 'percentile' => round((float) $row['percentile'], 8), 'date' => $date];
    }

    private static function observations(string $code, array $row): array
    {
        $items = match ($code) {
            'urlhaus' => [$row['url'] ?? null],
            'threatfox' => [$row['ioc'] ?? null],
            'malwarebazaar' => [$row['sha256_hash'] ?? null, $row['sha1_hash'] ?? null, $row['md5_hash'] ?? null],
        };
        $result = [];
        foreach ($items as $item) {
            if (!is_string($item) || $item === '') {
                continue;
            }
            if ($code === 'threatfox' && preg_match('/^(\[[^]]+\]|[^:]+):([0-9]{1,5})$/D', $item, $ipPort)
                && filter_var(trim($ipPort[1], '[]'), FILTER_VALIDATE_IP)) {
                $item = trim($ipPort[1], '[]');
            }
            try {
                $value = Indicator::parse($item);
            } catch (\Sentinel\Core\Http) {
                continue;
            }
            if ($value['kind'] === 'cve' || ($code === 'urlhaus' && $value['kind'] !== 'url')
                || ($code === 'malwarebazaar' && !in_array($value['kind'], ['sha256','sha1','md5'], true))) {
                continue;
            }
            $result[] = ['normalized' => $value, 'category' => 'malware', 'confidence' => $row['confidence_level'] ?? null,
                'family' => $row['malware_printable'] ?? $row['signature'] ?? null, 'file_type' => $row['file_type'] ?? null,
                'first_seen' => $row['first_seen'] ?? $row['date_added'] ?? null, 'last_seen' => $row['last_seen'] ?? $row['last_online'] ?? null,
                'observed_state' => $row['url_status'] ?? $row['threat_type'] ?? null,
                'reference' => $row['urlhaus_reference'] ?? $row['reference'] ?? null, 'tags' => $row['tags'] ?? [], 'parser' => $code . '-1'];
        }
        return $result;
    }
}
