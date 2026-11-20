<?php
declare(strict_types=1);
namespace Sentinel\Core;

use PDO;
use PDOException;

final class DeploymentUnit
{
    private static function configured(): string
    {
        $unit = config('APP_UNIT');
        if ($unit !== '' && !preg_match('/^[a-z0-9][a-z0-9-]{0,31}$/D', $unit)) {
            throw new \RuntimeException('Kode APP_UNIT tidak valid.');
        }
        return $unit;
    }

    private static function marker(): string
    {
        return BASE . '/storage/.sentinel-unit';
    }

    public static function verify(PDO $pdo): void
    {
        $unit = self::configured();
        try {
            $database = $pdo->query('SELECT unit_code FROM deployment_unit WHERE id=1')->fetchColumn();
        } catch (PDOException $error) {
            if ($error->getCode() !== '42S02') {
                throw $error;
            }
            $database = false;
        }
        $marker = self::marker();
        $storage = file_exists($marker) || is_link($marker) ? trim((string) file_get_contents($marker)) : null;
        if (($database !== false && $database !== $unit) || ($storage !== null && $storage !== $unit)) {
            throw new \RuntimeException('Database atau penyimpanan terikat ke unit berbeda.');
        }
        if ($unit !== '' && !defined('SENTINEL_UNIT_SETUP') && ($database === false || $storage === null)) {
            throw new \RuntimeException('Unit harus diikat pada database dan penyimpanan sebelum aplikasi dijalankan.');
        }
    }

    public static function bind(): void
    {
        $unit = self::configured();
        if ($unit === '') {
            throw new \RuntimeException('Tetapkan APP_UNIT sebelum mengikat unit.');
        }
        query('SELECT unit_code FROM deployment_unit WHERE id=1');
        $marker = self::marker();
        if (!is_file($marker)) {
            $old = umask(0077);
            try {
                $file = @fopen($marker, 'x');
            } finally {
                umask($old);
            }
            if ($file === false) {
                throw new \RuntimeException('Penyimpanan unit tidak dapat diikat.');
            }
            $written = fwrite($file, $unit . PHP_EOL);
            fclose($file);
            if ($written !== strlen($unit . PHP_EOL)) {
                unlink($marker);
                throw new \RuntimeException('Identitas penyimpanan unit tidak dapat disimpan.');
            }
        }
        query('INSERT IGNORE INTO deployment_unit (id,unit_code) VALUES (1,?)', [$unit]);
        self::verify(db());
    }
}
