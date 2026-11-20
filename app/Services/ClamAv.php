<?php
declare(strict_types=1);
namespace Sentinel\Services;

final class ClamAv
{
    public static function scan(string $path): string
    {
        $socket = config('CLAMD_SOCKET');
        if ($socket === '') {
            return 'Belum diperiksa antivirus';
        }
        if (!str_starts_with($socket, '/') || preg_match('/[\x00-\x20]/', $socket)) {
            return 'ClamAV: tidak tersedia';
        }
        $deadline = hrtime(true) + 5_000_000_000;
        $connection = @stream_socket_client('unix://' . $socket, $errno, $error, 1);
        if ($connection === false) {
            return 'ClamAV: tidak tersedia';
        }
        $file = @fopen($path, 'rb');
        try {
            if ($file === false || !self::send($connection, "zINSTREAM\0", $deadline)) {
                return 'ClamAV: pemindaian gagal';
            }
            while (!feof($file)) {
                $chunk = fread($file, 65_536);
                if ($chunk === false || ($chunk !== '' && !self::send($connection, pack('N', strlen($chunk)) . $chunk, $deadline))) {
                    return 'ClamAV: pemindaian gagal';
                }
            }
            if (!self::send($connection, pack('N', 0), $deadline)) {
                return 'ClamAV: pemindaian gagal';
            }
            $reply = '';
            while (strlen($reply) < 1024 && self::setDeadline($connection, $deadline)) {
                $chunk = @fread($connection, 1024 - strlen($reply));
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $reply .= $chunk;
                if (str_contains($reply, "\0")) {
                    $result = strstr($reply, "\0", true);
                    if ($result === 'stream: OK') {
                        return 'ClamAV: tidak terdeteksi';
                    }
                    if (preg_match('/^stream: [^\r\n]{1,255} FOUND$/D', $result)) {
                        return 'ClamAV: terdeteksi';
                    }
                    break;
                }
            }
            return 'ClamAV: pemindaian gagal';
        } finally {
            if (is_resource($file)) {
                fclose($file);
            }
            fclose($connection);
        }
    }

    private static function setDeadline($connection, int $deadline): bool
    {
        $micros = intdiv($deadline - hrtime(true), 1000);
        return $micros > 0 && stream_set_timeout($connection, intdiv($micros, 1_000_000), $micros % 1_000_000);
    }

    private static function send($connection, string $data, int $deadline): bool
    {
        while ($data !== '') {
            if (!self::setDeadline($connection, $deadline) || !($written = @fwrite($connection, $data))) {
                return false;
            }
            $data = substr($data, $written);
        }
        return true;
    }
}
