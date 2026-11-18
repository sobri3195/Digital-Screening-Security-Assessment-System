<?php
declare(strict_types=1);
namespace Sentinel\Core;

final class Http extends \RuntimeException
{
    public function __construct(public readonly int $status, string $message)
    {
        parent::__construct($message);
    }

    public static function redirect(string $destination): never
    {
        header('Location: ' . $destination, true, 303);
        exit;
    }

    public static function json(array $data, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    public static function limit(string $name, int $limit, int $seconds = 60): void
    {
        $minute = intdiv(time(), $seconds);
        query('INSERT INTO api_limits (bucket, minute, hits) VALUES (?, ?, LAST_INSERT_ID(1)) ON DUPLICATE KEY UPDATE hits = LAST_INSERT_ID(hits + 1)', [$name, $minute]);
        if ((int) db()->lastInsertId() > $limit) {
            header('Retry-After: ' . ($seconds - time() % $seconds));
            throw new self(429, 'Terlalu banyak percobaan. Coba kembali nanti.');
        }
    }
}
