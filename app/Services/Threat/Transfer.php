<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;

final class Transfer
{
    private const LIMIT = 2000;
    private const EXPORT_LIMIT = 250;
    private const MAX_BYTES = 4 * 1024 * 1024;

    public static function upload(array $file, string $format, int $user): int
    {
        if (($file['error'] ?? null) !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'] ?? '')) {
            throw new Http(422, 'Pilih file CSV atau paket JSON.');
        }
        $body = file_get_contents($file['tmp_name'], false, null, 0, self::MAX_BYTES + 1);
        if ($body === false || strlen($body) > self::MAX_BYTES) {
            throw new Http(422, 'Ukuran file maksimum 4 MiB.');
        }
        $rows = $format === 'csv' ? self::csvRows($body) : self::unpack($body);
        if (!$rows || count($rows) > self::LIMIT) {
            throw new Http(422, 'File harus memuat 1–2000 observasi.');
        }
        $provider = (int) Store::provider('offline')['id'];
        return Store::transaction(static function () use ($rows, $provider, $body, $user): int {
            foreach ($rows as $position => $row) {
                if (!is_array($row) || !is_string($row['value'] ?? null)) {
                    throw new Http(422, 'Format observasi tidak valid pada baris ' . ($position + 1) . '.');
                }
                $value = $row['value'];
                $kind = str_starts_with($value, 'hxxp') ? 'url' : (str_contains($value, '[:]') ? 'ipv6' : 'domain');
                $row['value'] = self::refang($value, $kind);
                if (is_string($row['reference'] ?? null)) {
                    $row['reference'] = self::refang($row['reference'], 'url');
                }
                Store::indicator($provider, $row);
            }
            query("INSERT INTO ti_transfers (user_id,action,file_sha256,rows_total) VALUES (?, 'import', ?, ?)", [$user, hash('sha256', $body), count($rows)]);
            audit($user, 'import', 'threat');
            return count($rows);
        });
    }

    public static function export(string $format, int $user, int $after): never
    {
        $rows = query('SELECT i.id,i.kind,i.fingerprint,i.display_value,p.code,s.category,s.severity,s.confidence,s.malware_family,s.first_seen,s.last_seen,
            s.expires_at,s.reference_text FROM ti_indicators i JOIN ti_indicator_sources s ON s.indicator_id=i.id
            JOIN ti_providers p ON p.id=s.provider_id WHERE i.id>? ORDER BY i.id,s.provider_id LIMIT ' . (self::EXPORT_LIMIT + 20), [$after])->fetchAll();
        if (count($rows) > self::EXPORT_LIMIT) {
            $last = (int) $rows[self::EXPORT_LIMIT]['id'];
            $rows = array_values(array_filter(array_slice($rows, 0, self::EXPORT_LIMIT), static fn ($row) => (int) $row['id'] !== $last));
        }
        $items = [];
        $skipped = 0;
        foreach ($rows as $row) {
            $value = self::refang($row['display_value'], $row['kind']);
            try {
                $normalized = Indicator::parse($value);
            } catch (Http) {
                $skipped++;
                continue;
            }
            if ($row['fingerprint'] !== $normalized['fingerprint']) {
                $skipped++;
                continue; // URLs with redacted params cannot be reconstructed from the export safely.
            }
            $items[] = ['value' => $row['display_value'], 'category' => $row['category'], 'severity' => $row['severity'], 'confidence' => $row['confidence'],
                'family' => $row['malware_family'], 'first_seen' => self::gmt($row['first_seen']), 'last_seen' => self::gmt($row['last_seen']),
                'expires_at' => self::gmt($row['expires_at']), 'reference' => $row['reference_text'],
                'origin_provider' => $row['code']];
        }
        $next = $rows ? (int) end($rows)['id'] : $after;
        $csv = $format === 'csv';
        $output = $csv ? self::toCsv($items) : self::pack($items, $next, $skipped);
        query("INSERT INTO ti_transfers (user_id,action,file_sha256,rows_total) VALUES (?, 'export', ?, ?)", [$user, hash('sha256', $output), count($items)]);
        audit($user, 'export', 'threat');
        header('Content-Type: ' . ($csv ? 'text/csv' : 'application/json') . '; charset=utf-8');
        header('Content-Disposition: attachment; filename="sentinel-ioc.' . ($csv ? 'csv' : 'json') . '"');
        header('X-Sentinel-Next-After: ' . $next);
        header('X-Sentinel-Excluded-Redacted: ' . $skipped);
        echo $output;
        exit;
    }

    private static function gmt(?string $value): ?string
    {
        return $value === null ? null : gmdate('Y-m-d\TH:i:s\Z', strtotime($value));
    }

    private static function refang(string $value, string $kind): string
    {
        $value = str_replace('[.]', '.', $value);
        return match ($kind) {
            'url' => preg_replace('~^hxxp(s?)://~D', 'http$1://', $value),
            'ipv6' => str_replace('[:]', ':', $value),
            default => $value,
        };
    }

    public static function pack(array $rows, int $next, int $excluded): string
    {
        $payload = base64_encode(Store::json($rows));
        return Store::json(['format' => 'sentinel-ioc-v1', 'sha256' => hash('sha256', $payload),
            'next_after' => $next, 'excluded_redacted' => $excluded, 'payload' => $payload]);
    }

    public static function unpack(string $raw): array
    {
        try {
            $box = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($box) || ($box['format'] ?? null) !== 'sentinel-ioc-v1' || !is_string($box['payload'] ?? null)
                || !is_string($box['sha256'] ?? null) || !hash_equals(hash('sha256', $box['payload']), $box['sha256'])) {
                throw new Http(422, 'Format atau checksum paket tidak valid.');
            }
            $json = base64_decode($box['payload'], true);
            $rows = $json === false ? null : json_decode($json, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($rows) || !array_is_list($rows)) {
                throw new Http(422, 'Isi paket tidak valid.');
            }
            return $rows;
        } catch (\JsonException) {
            throw new Http(422, 'JSON paket tidak valid.');
        }
    }

    private static function csvRows(string $body): array
    {
        $stream = fopen('php://temp', 'w+b');
        fwrite($stream, $body);
        rewind($stream);
        $header = fgetcsv($stream, null, ',', '"', '');
        $allowed = ['value','category','severity','confidence','family','first_seen','last_seen','expires_at','reference','origin_provider'];
        if (!is_array($header) || !in_array('value', $header, true) || array_diff($header, $allowed)
            || count(array_unique($header)) !== count($header)) {
            throw new Http(422, 'Header CSV tidak valid. Kolom value wajib.');
        }
        $rows = [];
        while (($line = fgetcsv($stream, null, ',', '"', '')) !== false) {
            if (count($line) !== count($header) || count($rows) >= self::LIMIT) {
                throw new Http(422, 'Baris CSV tidak valid atau melebihi 2000 observasi.');
            }
            $rows[] = array_combine($header, $line);
        }
        fclose($stream);
        return $rows;
    }

    private static function toCsv(array $items): string
    {
        $stream = fopen('php://temp', 'w+b');
        fputcsv($stream, ['value','category','severity','confidence','family','first_seen','last_seen','expires_at','reference','origin_provider'], ',', '"', '');
        foreach ($items as $row) {
            $safe = array_map(static fn ($item) => is_string($item) && preg_match('/^[\x00-\x20]*[=+@-]|^[\t\r\n]/', $item) ? "'" . $item : $item, $row);
            fputcsv($stream, $safe, ',', '"', '');
        }
        rewind($stream);
        $value = stream_get_contents($stream);
        fclose($stream);
        return $value;
    }
}
