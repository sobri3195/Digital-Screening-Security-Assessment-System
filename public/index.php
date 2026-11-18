<?php
declare(strict_types=1);

use Sentinel\Controllers\Api;
use Sentinel\Core\Auth;
use Sentinel\Core\Http;

header_remove('X-Powered-By');
ini_set('display_errors', '0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
header('Cache-Control: no-store');
header('Content-Type: text/html; charset=utf-8');

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$api = str_starts_with($path, '/api/v1/');
$user = null;
$modules = [];
try {
    require dirname(__DIR__) . '/app/Core/bootstrap.php';
    require BASE . '/routes/web.php';
    if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'POST'], true)) {
        throw new Http(405, 'Metode tidak didukung.');
    }
    if ($api) {
        Api::handle(substr($path, 8));
    }
    Auth::start();
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        Auth::verifyCsrf();
    }
    $user = Auth::user();
    $modules = require BASE . '/config/modules.php';
    [$template, $data] = dispatch_web($path, $user, $modules);
} catch (Throwable $error) {
    $status = $error instanceof Http ? $error->status : 500;
    $message = $error instanceof Http ? $error->getMessage() : 'Permintaan tidak dapat diproses. Hubungi administrator.';
    if ($status === 500) {
        error_log('Sentinel: ' . get_class($error) . ' at ' . basename($error->getFile()) . ':' . $error->getLine());
    }
    if ($api) {
        Http::json(['error' => $message], $status);
    }
    http_response_code($status);
    $template = $user === null && $status === 401 ? 'login' : 'error';
    $data = ['title' => $template === 'login' ? 'Masuk' : 'Terjadi kendala', 'message' => $message, 'status' => $status];
}
require BASE . '/app/Views/layout.php';
