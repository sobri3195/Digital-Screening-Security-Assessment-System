<?php
declare(strict_types=1);
namespace Sentinel\Services;

use Sentinel\Core\Http;

final class Inspection
{
    public static function url(string $url): array
    {
        if (strlen($url) > 2048 || preg_match('/[\x00-\x20\x7f]/', $url) || str_contains($url, '\\') || !filter_var($url, FILTER_VALIDATE_URL)) {
            throw new Http(422, 'Masukkan URL HTTP atau HTTPS yang valid (maksimal 2048 byte).');
        }
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = strtolower($parts['host'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            throw new Http(422, 'Hanya URL HTTP dan HTTPS yang didukung.');
        }
        $ip = filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) !== false;
        $labels = count(explode('.', trim($host, '.')));
        $indicators = [
            'Skema ' . strtoupper($scheme),
            'Panjang URL ' . strlen($url) . ' byte',
            $ip ? 'Hostname berupa alamat IP' : 'Jumlah label hostname ' . $labels,
        ];
        foreach ([
            [$scheme === 'http', 'URL menggunakan HTTP tanpa TLS'],
            [$labels > 4 && !$ip, 'Banyak label hostname; periksa domain tujuan'],
            [preg_match('/(?:^|\.)xn--/i', $host), 'Hostname menggunakan punycode'],
            [isset($parts['user']), 'URL memuat bagian userinfo yang dapat mengaburkan tujuan'],
            [preg_match('/%[0-9a-f]{2}/i', $url), 'URL memuat karakter dengan percent-encoding'],
            [strpbrk($url, '@#!$&') !== false, 'URL memuat karakter khusus'],
            [preg_match('/(?:login|verify|password|reset)/i', $parts['path'] ?? ''), 'Jalur memuat istilah autentikasi'],
        ] as [$matched, $note]) {
            if ($matched) {
                $indicators[] = $note;
            }
        }
        // Avoid recording URL credentials, fragments, or query parameters.
        $stored = $scheme . '://' . $host . (isset($parts['port']) ? ':' . $parts['port'] : '') . ($parts['path'] ?? '');
        return ['title' => $stored, 'host' => $host, 'indicators' => implode("\n", $indicators)];
    }

    public static function upload(array $file, int $userId): void
    {
        if (($file['error'] ?? null) !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'] ?? '')) {
            throw new Http(422, 'Upload gagal atau file belum dipilih.');
        }
        $path = $file['tmp_name'];
        $size = filesize($path);
        if (!$size || $size > 10 * 1024 * 1024) {
            throw new Http(422, 'Ukuran file harus antara 1 byte dan 10 MiB.');
        }
        $name = mb_substr(basename(str_replace('\\', '/', $file['name'])), 0, 255);
        $extension = strtolower(mb_substr(pathinfo($name, PATHINFO_EXTENSION), 0, 40));
        $mime = (new \finfo(FILEINFO_MIME_TYPE))->file($path);
        $types = [
            'txt' => ['text/plain'], 'csv' => ['text/plain', 'text/csv'], 'pdf' => ['application/pdf'],
            'png' => ['image/png'], 'jpg' => ['image/jpeg'], 'jpeg' => ['image/jpeg'],
            'zip' => ['application/zip'], 'json' => ['application/json'],
        ];
        if (!is_string($mime) || $mime === '' || strlen($mime) > 255) {
            throw new Http(422, 'MIME file tidak dapat diidentifikasi.');
        }
        $mismatch = !isset($types[$extension]) ? 'Ekstensi tidak dipetakan'
            : (in_array($mime, $types[$extension], true) ? 'Tidak terdeteksi' : 'Terdeteksi');
        $sha = hash_file('sha256', $path);
        $md5 = hash_file('md5', $path);
        if ($sha === false || $md5 === false) {
            throw new \RuntimeException('Hash file tidak dapat dihitung.');
        }
        $duplicate = query('SELECT id FROM file_inspections WHERE sha256 = ? ORDER BY id LIMIT 1', [$sha])->fetchColumn();
        $directory = BASE . '/storage/uploads';
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new \RuntimeException('Direktori file tidak tersedia.');
        }
        $key = bin2hex(random_bytes(16));
        $target = $directory . '/' . $key;
        if (!move_uploaded_file($path, $target)) {
            throw new \RuntimeException('File tidak dapat disimpan.');
        }
        try {
            chmod($target, 0600);
            query('INSERT INTO file_inspections (title,mime,extension,bytes,md5_hash,sha256,duplicate_of,mismatch,scan_status,storage_name,retained_until,user_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,NOW() + INTERVAL 30 DAY,?)',
                [$name, $mime, $extension, $size, $md5, $sha, $duplicate ?: null, $mismatch, ClamAv::scan($target), $key, $userId]);
        } catch (\Throwable $error) {
            unlink($target);
            throw $error;
        }
    }
    public static function scanStored(int $id): void
    {
        $record = query('SELECT storage_name,sha256 FROM file_inspections WHERE id=? AND retained_until>NOW()', [$id])->fetch();
        if (!$record || !is_string($record['storage_name']) || !preg_match('/^[a-f0-9]{32}$/D', $record['storage_name'])) {
            throw new Http(404, 'File privat tidak tersedia atau masa retensinya berakhir.');
        }
        $path = BASE . '/storage/uploads/' . $record['storage_name'];
        if (is_link($path) || !is_file($path) || @hash_file('sha256', $path) !== $record['sha256']) {
            throw new Http(422, 'File privat tidak lolos pemeriksaan integritas.');
        }
        $status = ClamAv::scan($path);
        query('UPDATE file_inspections SET scan_status=? WHERE id=? AND storage_name=? AND retained_until>NOW()',
            [$status, $id, $record['storage_name']]);
    }
}
