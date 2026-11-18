<?php
declare(strict_types=1);
namespace Sentinel\Services;

final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generate(): string
    {
        $secret = '';
        foreach (str_split(random_bytes(32)) as $byte) {
            $secret .= self::ALPHABET[ord($byte) & 31];
        }
        return $secret;
    }

    public static function verify(string $secret, string $code, int $last, ?int $time = null): ?int
    {
        if (!preg_match('/^\d{6}$/D', $code)) {
            return null;
        }
        $bits = '';
        foreach (str_split($secret) as $character) {
            $value = strpos(self::ALPHABET, $character);
            if ($value === false) {
                return null;
            }
            $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
        }
        $key = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $key .= chr(bindec($byte));
            }
        }
        $step = intdiv($time ?? time(), 30);
        for ($counter = max(0, $step - 1); $counter <= $step + 1; $counter++) {
            $hash = hash_hmac('sha1', pack('J', $counter), $key, true);
            $offset = ord($hash[19]) & 15;
            $number = unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff;
            if ($counter > $last && hash_equals(sprintf('%06d', $number % 1000000), $code)) {
                return $counter;
            }
        }
        return null;
    }
}
