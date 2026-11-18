<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

use Sentinel\Core\Http;

final class Indicator
{
    public const KINDS = ['url','domain','ipv4','ipv6','md5','sha1','sha256','cve'];

    public static function parse(string $input): array
    {
        $input = trim($input);
        if ($input === '' || strlen($input) > 2048 || preg_match('/[\x00-\x20\x7f]/', $input)
            || !mb_check_encoding($input, 'UTF-8') || str_contains($input, '\\')) {
            throw new Http(422, 'Masukkan satu URL, domain, IP, hash, atau CVE yang valid.');
        }
        $host = null;
        $scope = null;
        $facts = [];
        if (preg_match('/^CVE-[0-9]{4}-[0-9]{4,19}$/iD', $input)) {
            $kind = 'cve';
            $canonical = strtoupper($input);
        } elseif (ctype_xdigit($input) && ($kind = [32 => 'md5', 40 => 'sha1', 64 => 'sha256'][strlen($input)] ?? null)) {
            $canonical = strtolower($input);
        } elseif (filter_var($input, FILTER_VALIDATE_IP)) {
            [$kind, $canonical, $scope] = self::address($input);
            $facts[] = 'Klasifikasi IP: ' . $scope;
        } elseif (preg_match('~^https?://~i', $input)) {
            $kind = 'url';
            $parts = parse_url($input);
            if ($parts === false || !isset($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
                throw new Http(422, 'URL harus memiliki hostname dan bebas dari kredensial.');
            }
            $bare = trim($parts['host'], '[]');
            if (filter_var($bare, FILTER_VALIDATE_IP)) {
                [, $host, $scope] = self::address($bare);
                $facts[] = 'Hostname berupa alamat IP: ' . $scope;
            } else {
                $host = self::domain($bare);
            }
            $scheme = strtolower($parts['scheme']);
            $port = $parts['port'] ?? null;
            if ($port === 0) {
                throw new Http(422, 'Port URL tidak valid.');
            }
            $authority = str_contains($host, ':') ? '[' . $host . ']' : $host;
            if ($port !== null && $port !== ($scheme === 'https' ? 443 : 80)) {
                $authority .= ':' . $port;
            }
            $path = $parts['path'] ?? '/';
            if ($path === '') {
                $path = '/';
            }
            $shown = $scheme . '://' . $authority . $path;
            $canonical = $shown . (isset($parts['query']) ? '?' . $parts['query'] : '');
            $facts[] = strtoupper($scheme) . ' · ' . strlen($input) . ' byte';
            $facts[] = $scope === null ? 'Jumlah label hostname: ' . count(explode('.', $host)) : 'Alamat IP literal';
            if (preg_match('/%[a-f0-9]{2}/i', $input)) {
                $facts[] = 'Pengodean persen pada input';
            }
            if (in_array($host, ['bit.ly','t.co','tinyurl.com','is.gd','ow.ly'], true)) {
                $facts[] = 'Hostname tercatat sebagai pemendek tautan';
            }
        } else {
            $kind = 'domain';
            $canonical = $host = self::domain($input);
        }
        if ($host !== null && preg_match('/(?:^|\.)xn--/', $host)) {
            $facts[] = 'Hostname menggunakan punycode';
        }
        return [
            'kind' => $kind, 'fingerprint' => hash('sha256', $canonical),
            'value' => self::defang($shown ?? $canonical, $kind), 'host' => $host,
            'scope' => $scope, 'facts' => $facts, 'cve' => $kind === 'cve' ? $canonical : null,
        ];
    }

    private static function address(string $ip): array
    {
        $packed = inet_pton($ip);
        $kind = strlen($packed) === 4 ? 'ipv4' : 'ipv6';
        $canonical = inet_ntop($packed);
        $effective = str_starts_with($canonical, '::ffff:') && str_contains($canonical, '.') ? substr($canonical, 7) : $canonical;
        $scope = filter_var($effective, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) ? 'global' : 'non-global';
        return [$kind, $canonical, $scope];
    }

    public static function domain(string $value): string
    {
        $domain = idn_to_ascii(rtrim($value, '.'), IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_USE_STD3_RULES, INTL_IDNA_VARIANT_UTS46, $info);
        if ($domain === false || $info['errors'] || strlen($domain) > 253 || !str_contains($domain, '.')
            || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
            || preg_match('/^[0-9.]+$/D', $domain)) {
            throw new Http(422, 'Domain tidak valid.');
        }
        return strtolower($domain);
    }

    public static function defang(string $value, string $kind = 'url'): string
    {
        if ($kind === 'url') {
            $value = preg_replace('~^https?://~i', str_starts_with(strtolower($value), 'https://') ? 'hxxps://' : 'hxxp://', $value);
        }
        return match ($kind) {
            'url', 'domain', 'ipv4' => str_replace('.', '[.]', $value),
            'ipv6' => str_replace(':', '[:]', $value),
            default => $value,
        };
    }

    public static function reference(mixed $input): ?string
    {
        if (!is_string($input) || !preg_match('~^https?://~i', $input)) {
            return null;
        }
        try {
            return mb_substr(self::parse($input)['value'], 0, 1000);
        } catch (Http) {
            return null;
        }
    }
}
