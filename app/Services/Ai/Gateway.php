<?php
declare(strict_types=1);

namespace Sentinel\Services\Ai;

use Sentinel\Core\Auth;
use Sentinel\Core\Http;

final class Gateway
{
    public static function scopes(): array
    {
        return (require BASE . '/config/ai.php')['permissions'];
    }

    public static function sessionScopes(array $user): array
    {
        return array_values(array_filter(self::scopes(), static fn (string $scope) => Auth::allows($user, $scope)));
    }

    public static function configured(): bool
    {
        return function_exists('curl_init') && config('AI_GATEWAY_URL') !== '' && preg_match('/^[a-f0-9]{64}$/D', config('AI_WEB_KEY'));
    }

    private static function base(): array
    {
        if (!self::configured()) {
            throw new Http(503, 'AI Gateway belum dikonfigurasi.');
        }
        $url = config('AI_GATEWAY_URL');
        $parts = parse_url($url);
        $host = trim($parts['host'] ?? '', '[]');
        $scheme = $parts['scheme'] ?? '';
        $loopback = in_array($host, ['127.0.0.1', '::1'], true);
        $packed = filter_var($host, FILTER_VALIDATE_IP) ? inet_pton($host) : false;
        $private = is_string($packed) && (strlen($packed) === 4
            ? ord($packed[0]) === 10 || (ord($packed[0]) === 172 && (ord($packed[1]) & 240) === 16) || (ord($packed[0]) === 192 && ord($packed[1]) === 168)
            : (ord($packed[0]) & 254) === 252);
        if ((!$loopback && (!$private || $scheme !== 'https')) || ($loopback && !in_array($scheme, ['http', 'https'], true))
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)
            || !preg_match('~^https?://(?:\[[0-9a-f:]+\]|[0-9.]+)(?::[1-9][0-9]{0,4})?/?$~iD', $url)) {
            throw new Http(503, 'AI Gateway harus memakai IP loopback atau IP privat dengan HTTPS.');
        }
        return [rtrim($url, '/'), $loopback];
    }

    private static function b64(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    public static function request(string $method, string $path, string $subject, array $scopes, ?array $json = null): array
    {
        [$base, $loopback] = self::base();
        $tokenData = self::b64(json_encode(['sub'=>$subject, 'aud'=>'sentinel-ai', 'exp'=>time()+60,
            'scopes'=>array_values(array_intersect(self::scopes(), $scopes))], JSON_THROW_ON_ERROR));
        $token = 'v1.' . $tokenData . '.' . self::b64(hash_hmac('sha256', 'v1.' . $tokenData, hex2bin(config('AI_WEB_KEY')), true));
        $curl = curl_init($base . '/api/v1/ai' . $path);
        $output = '';
        $body = ['Accept: application/json', 'Authorization: Bearer ' . $token];
        if ($json !== null) {
            $body[] = 'Content-Type: application/json';
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($json, JSON_THROW_ON_ERROR));
        }
        curl_setopt_array($curl, [
            CURLOPT_CUSTOMREQUEST=>$method, CURLOPT_FOLLOWLOCATION=>false, CURLOPT_PROTOCOLS=>CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2, CURLOPT_TIMEOUT=>8, CURLOPT_CONNECTTIMEOUT=>2,
            CURLOPT_HTTPHEADER=>$body, CURLOPT_WRITEFUNCTION=>static function ($connection, string $chunk) use (&$output): int {
                if (strlen($output) + strlen($chunk) > 2 * 1024 * 1024) {
                    return 0;
                }
                $output .= $chunk;
                return strlen($chunk);
            },
        ]);
        if ($loopback) {
            curl_setopt($curl, CURLOPT_NOPROXY, '*');
        }
        $success = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        if (!$success || !$status || $status >= 500 || $status === 401 || ($status >= 300 && $status < 400)) {
            throw new Http(503, 'AI Gateway tidak tersedia. Modul lain tetap dapat digunakan.');
        }
        $response = json_decode($output, true, 32);
        if (!is_array($response)) {
            throw new Http(503, 'Respons AI Gateway tidak valid.');
        }
        if ($status >= 400) {
            $codes = [
                'approval_invalid'=>'Persetujuan memerlukan peninjau yang berbeda dari pengusul.',
                'review_invalid'=>'Draf harus ditinjau oleh petugas yang berbeda.',
                'insufficient_evidence'=>'Hasil tanpa bukti yang cukup tidak dapat disetujui.',
                'duplicate_document'=>'Konten atau versi ini sudah terdaftar.',
                'duplicate_model'=>'Model dan digest tersebut sudah terdaftar.',
                'queue_full'=>'Antrean penuh. Coba lagi setelah tugas selesai.',
                'invalid_input'=>'Data teknis atau pilihan tidak valid.',
                'model_not_installed'=>'Model belum terpasang pada runtime lokal.',
            ];
            $code = is_string($response['error'] ?? null) ? $response['error'] : '';
            throw new Http($status, $codes[$code] ?? 'Permintaan tidak dapat diproses oleh AI Gateway.');
        }
        return $response;
    }
}
