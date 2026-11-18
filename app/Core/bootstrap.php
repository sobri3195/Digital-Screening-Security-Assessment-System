<?php
declare(strict_types=1);

define('BASE', dirname(__DIR__, 2));
date_default_timezone_set('Asia/Jakarta');
if (is_file(BASE . '/.env')) {
    $config = parse_ini_file(BASE . '/.env', false, INI_SCANNER_RAW);
    if ($config === false) {
        throw new RuntimeException('Konfigurasi .env tidak valid.');
    }
    foreach ($config as $key => $value) {
        if (getenv($key) === false && is_string($value)) {
            putenv($key . '=' . $value);
        }
    }
}
if (is_file(BASE . '/vendor/autoload.php')) {
    require BASE . '/vendor/autoload.php';
}
spl_autoload_register(static function (string $name): void {
    if (str_starts_with($name, 'Sentinel\\')) {
        $path = BASE . '/app/' . str_replace('\\', '/', substr($name, 9)) . '.php';
        if (is_file($path)) {
            require $path;
        }
    }
});

function config(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false ? $default : $value;
}

function db(): PDO
{
    static $pdo;
    if ($pdo === null) {
        $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            config('DB_HOST', '127.0.0.1'), config('DB_PORT', '3306'), config('DB_NAME', 'puskesau_sentinel'));
        $pdo = new PDO($dsn, config('DB_USER', 'sentinel'), config('DB_PASSWORD'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec("SET time_zone = '+07:00'");
    }
    return $pdo;
}

function query(string $sql, array $args = []): PDOStatement
{
    $statement = db()->prepare($sql);
    $statement->execute($args);
    return $statement;
}

function escape(string|int|null $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function text_input(array $source, string $key): string
{
    $value = $source[$key] ?? '';
    return is_string($value) ? trim($value) : '';
}

function audit(?int $user, string $action, string $module, string $result = 'berhasil'): void
{
    query('INSERT INTO audit_logs (user_id, action, module, result) VALUES (?, ?, ?, ?)', [$user, $action, $module, $result]);
}
