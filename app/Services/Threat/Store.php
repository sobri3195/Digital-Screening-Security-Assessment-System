<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;

final class Store
{
    public const SEVERITIES = ['informational','low','medium','high','critical','unknown'];
    public const CATEGORIES = ['malware','phishing','ransomware','botnet','unknown'];
    public const ASSET_STATES = ['tidak_diketahui','potensial','terkonfirmasi','tidak_terdampak','dimitigasi'];

    public static function transaction(callable $operation): mixed
    {
        db()->beginTransaction();
        try {
            $result = $operation();
            db()->commit();
            return $result;
        } catch (\Throwable $error) {
            if (db()->inTransaction()) {
                db()->rollBack();
            }
            throw $error;
        }
    }

    public static function json(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    public static function text(mixed $value, int $limit): ?string
    {
        if (!is_string($value) || !mb_check_encoding($value, 'UTF-8')) {
            return null;
        }
        $trimmed = trim(preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', strip_tags($value)));
        return $trimmed === '' ? null : mb_substr($trimmed, 0, $limit);
    }

    public static function date(mixed $value, bool $withTime = false): ?string
    {
        if (!is_string($value) || !preg_match('/^([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?$/D', $value, $parts)
            || !checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1])) {
            return null;
        }
        if (!$withTime) {
            return substr($value, 0, 10);
        }
        try {
            return (new \DateTimeImmutable($value, new \DateTimeZone('UTC')))
                ->setTimezone(new \DateTimeZone('Asia/Jakarta'))->format('Y-m-d H:i:s');
        } catch (\Exception) {
            return null;
        }
    }

    public static function provider(string $code): array
    {
        $result = query('SELECT * FROM ti_providers WHERE code=?', [$code])->fetch();
        if (!$result) {
            throw new Http(404, 'Sumber data tidak ditemukan.');
        }
        return $result;
    }

    public static function indicator(int $provider, array $row): bool
    {
        $indicator = isset($row['normalized']) ? $row['normalized'] : Indicator::parse((string) ($row['value'] ?? ''));
        if ($indicator['kind'] === 'cve') {
            throw new Http(422, 'Gunakan katalog kerentanan untuk CVE.');
        }
        $category = in_array($row['category'] ?? null, self::CATEGORIES, true) ? $row['category'] : 'unknown';
        $severity = in_array($row['severity'] ?? null, self::SEVERITIES, true) ? $row['severity'] : 'unknown';
        $confidence = filter_var($row['confidence'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 100]]);
        $evidence = [
            'value' => $indicator['value'], 'category' => $category, 'severity' => $severity,
            'confidence' => $confidence === false ? null : $confidence,
            'family' => self::text($row['family'] ?? null, 120),
            'file_type' => self::text($row['file_type'] ?? null, 100),
            'first_seen' => self::date($row['first_seen'] ?? null, true),
            'last_seen' => self::date($row['last_seen'] ?? null, true),
            'expires_at' => self::date($row['expires_at'] ?? null, true),
            'reference' => Indicator::reference($row['reference'] ?? null),
            'observed_state' => self::text($row['observed_state'] ?? null, 40),
            'origin_provider' => self::text($row['origin_provider'] ?? null, 60),
            'tags' => array_values(array_filter(array_map(static fn ($tag) => self::text($tag, 50), array_slice(is_array($row['tags'] ?? null) ? $row['tags'] : [], 0, 15)))),
            'parser' => self::text($row['parser'] ?? null, 30) ?? 'manual-1',
        ];
        if ($indicator['kind'] === 'url' && mb_strlen($indicator['value']) > 2048) {
            $evidence['value'] = mb_substr($indicator['value'], 0, 2048);
        }
        query('INSERT INTO ti_indicators (kind,fingerprint,display_value,host,ip_scope) VALUES (?,?,?,?,?)
            ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)', [$indicator['kind'], $indicator['fingerprint'], $evidence['value'], $indicator['host'], $indicator['scope']]);
        $id = (int) db()->lastInsertId();
        $json = self::json($evidence);
        $checksum = hash('sha256', $json);
        $existing = query('SELECT evidence_sha256 FROM ti_indicator_sources WHERE indicator_id=? AND provider_id=? FOR UPDATE', [$id, $provider])->fetchColumn();
        query('INSERT INTO ti_indicator_sources (indicator_id,provider_id,category,severity,confidence,malware_family,first_seen,last_seen,expires_at,reference_text,evidence,evidence_sha256,parser_version)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE
            verified_at=IF(evidence_sha256=VALUES(evidence_sha256),verified_at,NULL),category=VALUES(category),severity=VALUES(severity),
            confidence=VALUES(confidence),malware_family=VALUES(malware_family),first_seen=COALESCE(VALUES(first_seen),first_seen),
            last_seen=COALESCE(VALUES(last_seen),last_seen),expires_at=VALUES(expires_at),reference_text=VALUES(reference_text),
            evidence=VALUES(evidence),evidence_sha256=VALUES(evidence_sha256),parser_version=VALUES(parser_version),retrieved_at=NOW()',
            [$id, $provider, $category, $severity, $evidence['confidence'], $evidence['family'], $evidence['first_seen'], $evidence['last_seen'],
                $evidence['expires_at'], $evidence['reference'], $json, $checksum, $evidence['parser']]);
        return $existing !== $checksum;
    }

    public static function applyKevSnapshot(array $rows, int $job): int
    {
        $active = array_column(query('SELECT id,cve,kev_added_on,kev_evidence,kev_evidence_sha256
            FROM ti_vulnerabilities WHERE kev_added_on IS NOT NULL FOR UPDATE')->fetchAll(), null, 'cve');
        $unchanged = 0;
        foreach ($rows as $row) {
            $cve = $row['cve'];
            $unchanged += (int) !self::vulnerability('cisa', $row);
            if (!isset($active[$cve])) {
                $id = query('SELECT id FROM ti_vulnerabilities WHERE cve=?', [$cve])->fetchColumn();
                $evidence = self::json($row);
                query("INSERT INTO ti_kev_history (vulnerability_id,sync_job_id,status,evidence,evidence_sha256) VALUES (?,?,'added',?,?)",
                    [$id, $job, $evidence, hash('sha256', $evidence)]);
            }
            unset($active[$cve]);
        }
        foreach ($active as $previous) {
            $evidence = $previous['kev_evidence'] ?? self::json(['cve' => $previous['cve'], 'added' => $previous['kev_added_on']]);
            query("INSERT INTO ti_kev_history (vulnerability_id,sync_job_id,status,evidence,evidence_sha256) VALUES (?,?,'removed',?,?)",
                [$previous['id'], $job, $evidence, $previous['kev_evidence_sha256'] ?? hash('sha256', $evidence)]);
            query('UPDATE ti_vulnerabilities SET kev_added_on=NULL,kev_due_on=NULL,kev_title=NULL,kev_action=NULL,
                kev_ransomware=NULL,kev_evidence=NULL,kev_evidence_sha256=NULL WHERE id=?', [$previous['id']]);
        }
        return $unchanged;
    }

    public static function vulnerability(string $type, array $row): bool
    {
        if (!preg_match('/^CVE-[0-9]{4}-[0-9]{4,19}$/D', $row['cve'] ?? '')) {
            throw new Http(422, 'ID CVE tidak valid.');
        }
        $cve = $row['cve'];
        query('INSERT INTO ti_vulnerabilities (cve) VALUES (?) ON DUPLICATE KEY UPDATE cve=VALUES(cve)', [$cve]);
        if ($type === 'epss') {
            $on = $row['date'];
            if (!is_string($on) || !is_numeric($row['epss']) || !is_numeric($row['percentile'])
                || $row['epss'] < 0 || $row['epss'] > 1 || $row['percentile'] < 0 || $row['percentile'] > 1) {
                throw new Http(422, 'Skor EPSS tidak valid.');
            }
            $previous = query('SELECT epss,epss_percentile,epss_on FROM ti_vulnerabilities WHERE cve=?', [$cve])->fetch();
            query('UPDATE ti_vulnerabilities SET epss=?,epss_percentile=?,epss_on=?,epss_retrieved_at=NOW()
                WHERE cve=? AND (epss_on IS NULL OR epss_on<=?)', [$row['epss'], $row['percentile'], $on, $cve, $on]);
            return ($previous['epss_on'] === null || $previous['epss_on'] <= $on)
                && ($previous['epss_on'] !== $on || (float) $previous['epss'] !== (float) $row['epss']
                    || (float) $previous['epss_percentile'] !== (float) $row['percentile']);
        }
        $json = self::json($row);
        $checksum = hash('sha256', $json);
        if ($type === 'cisa') {
            $original = query('SELECT kev_evidence_sha256 FROM ti_vulnerabilities WHERE cve=?', [$cve])->fetchColumn();
            query('UPDATE ti_vulnerabilities SET vendor=COALESCE(?,vendor),product=COALESCE(?,product),description=COALESCE(description,?),
                kev_title=?,kev_added_on=?,kev_due_on=?,kev_action=?,kev_ransomware=?,kev_evidence=?,kev_evidence_sha256=?,kev_retrieved_at=NOW() WHERE cve=?',
                [$row['vendor'], $row['product'], $row['description'], $row['title'], $row['added'], $row['due'], $row['action'], $row['ransomware'], $json, $checksum, $cve]);
            return $original !== $checksum;
        }
        $original = query('SELECT nvd_evidence_sha256,modified_at FROM ti_vulnerabilities WHERE cve=?', [$cve])->fetch();
        if ($original['modified_at'] !== null && ($row['modified'] === null || $row['modified'] < $original['modified_at'])) {
            return false;
        }
        query('UPDATE ti_vulnerabilities SET vendor=COALESCE(vendor,?),product=COALESCE(product,?),description=COALESCE(?,description),
            cvss=?,cvss_vector=?,severity=?,published_at=?,modified_at=?,nvd_evidence=?,nvd_evidence_sha256=?,nvd_retrieved_at=NOW() WHERE cve=?',
            [$row['vendor'], $row['product'], $row['description'], $row['cvss'], $row['vector'], $row['severity'], $row['published'], $row['modified'], $json, $checksum, $cve]);
        return $original['nvd_evidence_sha256'] !== $checksum;
    }

    public static function advisory(int $provider, string $publisher, array $input): int
    {
        $title = self::text($input['title'] ?? null, 220);
        $summary = self::text($input['summary'] ?? null, 8000);
        if ($title === null || $summary === null) {
            throw new Http(422, 'Judul dan ringkasan advisori wajib diisi.');
        }
        $reference = Indicator::reference($input['reference'] ?? null);
        $published = self::date($input['published'] ?? null);
        $fingerprint = hash('sha256', $title . "\n" . $published . "\n" . $reference);
        $severity = $input['severity'] ?? 'unknown';
        $cve = strtoupper((string) ($input['cve'] ?? ''));
        if ($cve !== '' && !preg_match('/^CVE-[0-9]{4}-[0-9]{4,19}$/D', $cve)) {
            throw new Http(422, 'ID CVE tidak valid.');
        }
        $row = [$title, $publisher, $published, in_array($severity, self::SEVERITIES, true) ? $severity : 'unknown',
            self::text($input['category'] ?? null, 40), self::text($input['product'] ?? null, 140), $cve ?: null,
            $summary, self::text($input['mitigation'] ?? null, 8000), $reference, (int) !empty($input['healthcare'])];
        query('INSERT INTO ti_advisories (provider_id,fingerprint,title,publisher,published_on,severity,category,product,cve,summary,mitigation,reference_text,healthcare,evidence_sha256)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), severity=VALUES(severity),
            category=VALUES(category),product=VALUES(product),cve=VALUES(cve),summary=VALUES(summary),mitigation=VALUES(mitigation),
            healthcare=VALUES(healthcare),evidence_sha256=VALUES(evidence_sha256),retrieved_at=NOW()',
            [$provider, $fingerprint, ...$row, hash('sha256', self::json($row))]);
        return (int) db()->lastInsertId();
    }

    public static function alert(string $key, string $category, string $title, string $severity, string $route): void
    {
        query('INSERT INTO ti_alerts (dedup_key,category,title,severity,route) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE last_seen=NOW(),severity=VALUES(severity)',
            [hash('sha256', $key), $category, mb_substr($title, 0, 220), $severity, $route]);
    }

    public static function setting(string $name): int
    {
        return (int) query('SELECT value FROM ti_settings WHERE name=?', [$name])->fetchColumn();
    }
}
