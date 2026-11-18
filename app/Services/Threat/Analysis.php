<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;

final class Analysis
{
    public const RULE = 'priority-1';
    private const POINTS = ['critical' => 45, 'high' => 35, 'medium' => 24, 'low' => 12, 'informational' => 5];

    public static function scan(string $input, ?int $user, ?int $client = null, string $expected = '', string $category = ''): array
    {
        $subject = Indicator::parse($input);
        $kind = $subject['kind'];
        if (($expected === 'ip' && !in_array($kind, ['ipv4','ipv6'], true))
            || ($expected === 'hash' && !in_array($kind, ['md5','sha1','sha256'], true))
            || ($expected !== '' && !in_array($expected, ['ip','hash'], true) && $kind !== $expected)) {
            throw new Http(422, 'Tipe input tidak sesuai halaman ini.');
        }
        $matches = $kind === 'cve' ? self::cve($subject['cve']) : self::sources($subject, $category);
        $similar = in_array($kind, ['url','domain'], true) && $subject['scope'] === null ? self::similarity($subject['host']) : [];
        $bonus = $kind === 'cve' ? self::vulnerabilityPriority($matches[0]['metadata'] ?? []) : self::indicatorPriority($matches);
        $facts = ['facts' => $subject['facts'], 'brand' => $similar, 'priority_reasons' => $bonus['components'], 'category' => $category];
        return Store::transaction(static function () use ($user, $client, $kind, $subject, $facts, $matches, $bonus): array {
            $displayValue = mb_substr($subject['value'], 0, 2048);
            query('INSERT INTO ti_scan_results (user_id,client_id,kind,display_value,facts,priority,rule_version) VALUES (?,?,?,?,?,?,?)',
                [$user, $client, $kind, $displayValue, Store::json($facts), $bonus['score'], self::RULE]);
            $id = (int) db()->lastInsertId();
            foreach ($matches as $i => $match) {
                query('INSERT INTO ti_scan_matches VALUES (?,?,?)', [$id, $i, Store::json($match)]);
            }
            if ($matches && $bonus['score'] >= Store::setting('alert_priority')) {
                Store::alert('scan:' . $subject['fingerprint'] . ':' . $facts['category'], 'pemeriksaan', 'Indikator pemeriksaan memerlukan tinjauan',
                    self::level($bonus['score']), '/threat/alerts');
            }
            audit($user, 'scan', 'threat');
            return ['id' => $id, 'kind' => $kind, 'display_value' => $displayValue, 'facts' => $facts, 'priority' => $bonus['score'], 'rule_version' => self::RULE, 'matches' => $matches];
        });
    }

    private static function cve(string $value): array
    {
        $row = query('SELECT id,cve,vendor,product,cvss,cvss_vector,severity,published_at,modified_at,kev_added_on,kev_due_on,
            kev_ransomware,epss,epss_percentile,epss_on,nvd_retrieved_at,kev_retrieved_at,epss_retrieved_at,
            nvd_evidence_sha256,kev_evidence_sha256 FROM ti_vulnerabilities WHERE cve=?', [$value])->fetch();
        return $row ? [['basis' => 'CVE identik dalam katalog lokal', 'metadata' => $row]] : [];
    }

    private static function sources(array $subject, string $category): array
    {
        $hashes = [[$subject['kind'], $subject['fingerprint'], 'Indikator persis']];
        if ($subject['kind'] === 'url' && $subject['host'] !== null) {
            $parent = Indicator::parse($subject['host']);
            $hashes[] = [$parent['kind'], $parent['fingerprint'], 'Hostname URL cocok dengan indikator tersendiri'];
        }
        $matches = [];
        foreach ($hashes as [$kind, $hash, $basis]) {
            $condition = $category !== '' ? ' AND s.category=?' : '';
            $values = $category !== '' ? [$kind,$hash,$category] : [$kind,$hash];
            $rows = query("SELECT i.id,i.display_value,p.code AS provider_code,p.title AS provider,s.category,s.severity,s.confidence,s.malware_family,
                s.first_seen,s.last_seen,s.expires_at,s.verified_at,s.reference_text,s.evidence_sha256,s.parser_version,s.retrieved_at,s.evidence
                FROM ti_indicators i JOIN ti_indicator_sources s ON s.indicator_id=i.id JOIN ti_providers p ON p.id=s.provider_id
                WHERE i.kind=? AND i.fingerprint=? AND (s.expires_at IS NULL OR s.expires_at>NOW())$condition ORDER BY s.verified_at DESC,p.id LIMIT 20", $values)->fetchAll();
            foreach ($rows as $row) {
                $row['evidence'] = json_decode($row['evidence'], true, 512, JSON_THROW_ON_ERROR);
                $matches[] = ['basis' => $basis, 'metadata' => $row];
            }
        }
        return $matches;
    }

    public static function similarity(?string $host): array
    {
        if ($host === null) {
            return [];
        }
        $checker = new \Spoofchecker();
        $unicode = idn_to_utf8($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        $domains = query('SELECT domain,title FROM ti_reference_domains WHERE active=1 ORDER BY id LIMIT 500')->fetchAll();
        foreach ($domains as $item) {
            if ($host === $item['domain'] || str_ends_with($host, '.' . $item['domain'])) {
                return [];
            }
        }
        $flags = [];
        foreach ($domains as $item) {
            $ref = $item['domain'];
            $distance = levenshtein($host, $ref);
            $lookalike = $unicode !== false && $checker->areConfusable($unicode, idn_to_utf8($ref, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46) ?: $ref);
            if (($distance <= 2 && strlen($ref) >= 6) || $lookalike) {
                $flags[] = ['domain' => Indicator::defang($ref, 'domain'), 'title' => $item['title'],
                    'basis' => $lookalike ? 'Karakter dapat tertukar menurut ICU' : 'Jarak edit: ' . $distance];
            }
        }
        return array_slice($flags, 0, 10);
    }

    public static function indicatorPriority(array $matches): array
    {
        $severity = $confidence = $verified = $fresh = 0;
        $providers = [];
        foreach ($matches as $match) {
            $data = $match['metadata'];
            $severity = max($severity, self::POINTS[$data['severity'] ?? ''] ?? 0);
            $confidence = max($confidence, (int) round(((int) ($data['confidence'] ?? 0)) * 0.2));
            $verified = max($verified, empty($data['verified_at']) ? 0 : 10);
            $last = $data['last_seen'] ?? $data['first_seen'] ?? null;
            $fresh = max($fresh, $last !== null && strtotime($last) >= time() - 30 * 86400 && strtotime($last) <= time() ? 10 : 0);
            $providers[$data['provider_code']] = true;
        }
        $points = ['severity' => $severity, 'confidence' => $confidence, 'terverifikasi' => $verified,
            'observasi_30_hari' => $fresh, 'sumber_tambahan' => min(15, max(0, count($providers) - 1) * 5)];
        return ['score' => array_sum($points), 'components' => $points];
    }

    public static function vulnerabilityPriority(array $data): array
    {
        $points = ['cvss' => (int) round((float) ($data['cvss'] ?? 0) * 5), 'kev' => empty($data['kev_added_on']) ? 0 : 30,
            'epss' => (int) round((float) ($data['epss'] ?? 0) * 20)];
        return ['score' => array_sum($points), 'components' => $points];
    }

    public static function level(int $score): string
    {
        return match (true) {
            $score >= 85 => 'critical', $score >= 65 => 'high', $score >= 40 => 'medium', $score >= 15 => 'low', default => 'informational',
        };
    }

    public static function assetCandidates(int $vulnerability): int
    {
        $record = query('SELECT * FROM ti_vulnerabilities WHERE id=?', [$vulnerability])->fetch();
        if (!$record) {
            throw new Http(404, 'Kerentanan tidak ditemukan.');
        }
        $evidence = json_decode($record['nvd_evidence'] ?? '{}', true) ?: [];
        $products = $evidence['products'] ?? [];
        if (!$products && $record['vendor'] && $record['product']) {
            $products[] = ['vendor' => $record['vendor'], 'product' => $record['product'], 'version' => '*'];
        }
        $count = 0;
        foreach (array_slice($products, 0, 50) as $product) {
            $vendor = str_replace('_', ' ', $product['vendor']);
            $name = str_replace('_', ' ', $product['product']);
            if ($vendor === '' || $name === '' || strpbrk($vendor . $name, '*?\\') !== false) {
                continue;
            }
            $assets = query("SELECT id,os_version FROM institutional_assets WHERE (brand=? AND model=?) OR os_name IN (?,?) ORDER BY id LIMIT 500",
                [$vendor, $name, $vendor . ' ' . $name, $name])->fetchAll();
            foreach ($assets as $asset) {
                if (!self::versions($asset['os_version'], $product)) {
                    continue;
                }
                $added = query('INSERT IGNORE INTO ti_asset_vulnerabilities (asset_id,vulnerability_id,basis) VALUES (?,?,?)',
                    [$asset['id'], $vulnerability, 'Kecocokan nama produk/vendor dan versi yang tersedia. Perlu verifikasi.'])->rowCount();
                $count += $added;
                if ($added && ($record['kev_added_on'] || $record['severity'] === 'critical')) {
                    Store::alert('asset:' . $asset['id'] . ':' . $vulnerability, 'aset', 'Tinjau kandidat aset untuk ' . $record['cve'], $record['severity'] === 'critical' ? 'critical' : 'high', '/threat/vulnerabilities?id=' . $vulnerability);
                }
            }
        }
        return $count;
    }

    public static function versions(?string $version, array $product): bool
    {
        $expected = $product['version'] ?? '*';
        if (!$version) {
            return true; // Unknown inventory versions remain unverified candidates.
        }
        if ($expected !== '*' && $expected !== '-' && $version !== $expected) {
            return false;
        }
        foreach (['start_including' => '>=', 'start_excluding' => '>', 'end_including' => '<=', 'end_excluding' => '<'] as $key => $operator) {
            $bound = $product[$key] ?? '';
            if (preg_match('/^\d+(?:\.\d+)*$/D', $version) && preg_match('/^\d+(?:\.\d+)*$/D', (string) $bound)
                && !version_compare($version, $bound, $operator)) {
                return false;
            }
        }
        return true;
    }
}
