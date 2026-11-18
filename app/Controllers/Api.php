<?php
declare(strict_types=1);
namespace Sentinel\Controllers;

use Sentinel\Core\Http;

final class Api
{
    private const ROUTES = [
        'assets' => ['institutional_assets', 'id, code, title, owner_unit, inspected_on'],
        'inspections' => ['inspection_schedules', 'id, title, activity_id, asset_id, scheduled_on, state'],
        'checklists' => ['security_checklists', 'id, title, asset_id, notes'],
        'findings' => ['security_findings', 'id, title, category, asset_id, severity, state'],
        'reports' => ['reports', 'id, code, title, source, inspected_on'],
    ];
    public const SCOPES = ['assets.read', 'inspections.read', 'checklists.read', 'findings.read', 'reports.read'];

    public static function handle(string $path): never
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $remote = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? '');
        Http::limit('api:' . $remote, 120);
        if ($path === 'health' && $method === 'GET') {
            query('SELECT 1');
            Http::json(['status' => 'ok', 'version' => '1.0.0']);
        }
        if ($path === 'auth/token' && $method === 'POST') {
            Http::limit('api-token:' . $remote, 10);
            $payload = file_get_contents('php://input', false, null, 0, 4097);
            $data = is_string($payload) ? json_decode($payload, true) : null;
            $clientId = $data['client_id'] ?? null;
            if (!is_string($payload) || strlen($payload) > 4096 || !is_array($data)
                || !(is_int($clientId) || is_string($clientId)) || !preg_match('/^[1-9][0-9]{0,9}$/D', (string) $clientId)
                || !is_string($data['client_secret'] ?? null) || !preg_match('/^[a-f0-9]{64}$/D', $data['client_secret'])) {
                throw new Http(422, 'Kredensial klien tidak valid.');
            }
            $client = query('SELECT * FROM api_clients WHERE id = ? AND active = 1', [$clientId])->fetch();
            if (!$client || !password_verify($data['client_secret'], $client['secret_hash'])) {
                audit(null, 'token', 'api', 'gagal');
                throw new Http(401, 'Kredensial klien tidak valid.');
            }
            $token = bin2hex(random_bytes(32));
            query('INSERT INTO api_tokens VALUES (?, ?, NOW() + INTERVAL 1 HOUR)', [hash('sha256', $token), $client['id']]);
            audit(null, 'token', 'api');
            Http::json(['access_token' => $token, 'token_type' => 'Bearer', 'expires_in' => 3600]);
        }
        if (!isset(self::ROUTES[$path])) {
            throw new Http(404, 'Endpoint tidak ditemukan.');
        }
        if ($method !== 'GET') {
            throw new Http(405, 'Metode tidak didukung.');
        }
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/^Bearer ([a-f0-9]{64})$/D', $header, $matches)) {
            throw new Http(401, 'Token dibutuhkan.');
        }
        $client = query('SELECT c.id,c.scopes FROM api_tokens t JOIN api_clients c ON c.id=t.client_id WHERE t.id=? AND t.expires_at > NOW() AND c.active=1', [hash('sha256', $matches[1])])->fetch();
        if (!$client) {
            throw new Http(401, 'Token tidak valid atau telah kedaluwarsa.');
        }
        if (!in_array($path . '.read', explode(',', $client['scopes'] ?? ''), true)) {
            audit(null, 'baca', 'api:' . $path, 'ditolak');
            throw new Http(403, 'Scope klien tidak mengizinkan endpoint ini.');
        }
        [$table, $columns] = self::ROUTES[$path];
        $where = $path === 'reports' ? "WHERE state = 'disetujui'" : '';
        $cursor = text_input($_GET, 'after');
        if ($cursor !== '' && !ctype_digit($cursor)) {
            throw new Http(422, 'Cursor harus berupa ID numerik.');
        }
        $condition = $where === '' ? 'WHERE' : 'AND';
        $rows = query("SELECT $columns FROM $table $where $condition id > ? ORDER BY id LIMIT 100", [$cursor ?: 0])->fetchAll();
        audit(null, 'baca', 'api:' . $path);
        Http::json(['data' => $rows, 'next_after' => count($rows) === 100 ? end($rows)['id'] : null]);
    }
}
