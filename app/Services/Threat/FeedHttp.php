<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

final class FeedHttp
{
    private const MAX_BYTES = 16 * 1024 * 1024;

    public static function request(string $url, array $headers = [], ?string $post = null): array
    {
        $body = '';
        $retryAfter = 0;
        $overflow = false;
        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => 'Puskesau-Sentinel/2.0 defensive-feed-client',
            CURLOPT_HTTPHEADER => ['Accept: application/json', ...$headers],
            CURLOPT_ENCODING => '',
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$retryAfter): int {
                if (preg_match('/^Retry-After:\s*(\d+)\s*$/iD', trim($line), $matches)) {
                    $retryAfter = min(86400, (int) $matches[1]);
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$overflow): int {
                if (strlen($body) + strlen($chunk) > self::MAX_BYTES) {
                    $overflow = true;
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        if ($post !== null) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
        }
        $success = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $error = curl_errno($curl);
        curl_close($curl);
        if ($overflow) {
            throw new FeedFailure('Respons feed melebihi 16 MiB.');
        }
        if ($status === 429 || $status >= 500) {
            throw new FeedFailure('Feed mengembalikan HTTP ' . $status . '.', true, $retryAfter);
        }
        if ($success === false) {
            throw new FeedFailure('Koneksi HTTPS feed gagal (cURL ' . $error . ').', true);
        }
        if ($status < 200 || $status >= 300) {
            throw new FeedFailure('Feed mengembalikan HTTP ' . $status . '. Periksa konfigurasi, izin, atau kebijakan jaringan.');
        }
        try {
            $json = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new FeedFailure('Respons feed bukan JSON yang valid.');
        }
        if (!is_array($json)) {
            throw new FeedFailure('Struktur JSON feed tidak dikenali.');
        }
        return $json;
    }
}
