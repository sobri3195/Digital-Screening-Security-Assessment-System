<?php
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (is_string($path) && str_starts_with($path, '/assets/')) {
    return false;
}
require dirname(__DIR__) . '/public/index.php';
