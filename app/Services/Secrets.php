<?php
declare(strict_types=1);
namespace Sentinel\Services;

final class Secrets
{
    private static function key(): string
    {
        $hex = config('APP_KEY');
        if (!preg_match('/^[a-f0-9]{64}$/iD', $hex)) {
            throw new \RuntimeException('APP_KEY harus berisi 32 byte dalam bentuk heksadesimal.');
        }
        return hex2bin($hex);
    }

    public static function seal(string $value): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce . sodium_crypto_secretbox($value, $nonce, self::key()));
    }

    public static function open(string $value): string
    {
        $data = base64_decode($value, true);
        if ($data === false || strlen($data) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new \RuntimeException('Format data terenkripsi tidak valid.');
        }
        $nonce = substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plaintext = sodium_crypto_secretbox_open(substr($data, strlen($nonce)), $nonce, self::key());
        if ($plaintext === false) {
            throw new \RuntimeException('Verifikasi data terenkripsi gagal.');
        }
        return $plaintext;
    }
}
