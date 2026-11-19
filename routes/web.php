<?php
declare(strict_types=1);

use Sentinel\Controllers\Dashboard;
use Sentinel\Controllers\Ai;
use Sentinel\Controllers\Profile;
use Sentinel\Controllers\Records;
use Sentinel\Controllers\Threat;
use Sentinel\Core\Auth;
use Sentinel\Core\Http;
use Sentinel\Services\Backup;
use Sentinel\Services\Branding;
use Sentinel\Services\Reports;

function dispatch_web(string $path, ?array $user, array $modules): array
{
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
    if ($path === '/login') {
        if ($user) {
            Http::redirect('/');
        }
        if ($post) {
            Auth::signIn();
            Http::redirect('/');
        }
        return ['login', ['title' => 'Masuk']];
    }
    if ($user === null) {
        Http::redirect('/login');
    }
    if ($path === '/logout' && $post) {
        Auth::signOut($user);
        Http::redirect('/login');
    }
    if ($path === '/institution-logo') {
        if ($post) {
            Auth::require($user, 'settings.write');
            Branding::upload($_FILES['logo'] ?? []);
            audit((int) $user['id'], 'ubah-logo', 'settings');
            $_SESSION['notice'] = 'Logo institusi diperbarui.';
            Http::redirect('/m/system_settings');
        }
        Branding::send();
    }
    if ($path === '/threat' && !$post) {
        Http::redirect('/threat/dashboard');
    }
    if (str_starts_with($path, '/threat/')) {
        return Threat::handle(substr($path, 8), $user, $post);
    }
    if ($path === '/ai' && !$post) {
        Http::redirect('/ai/dashboard');
    }
    if (str_starts_with($path, '/ai/')) {
        return Ai::handle(substr($path, 4), $user, $post);
    }
    if ($path === '/profile') {
        return ['profile', ['title' => 'Profil Saya'] + Profile::handle($user)];
    }
    if ($path === '/' && !$post) {
        if (!Auth::allows($user, 'dashboard.read')) {
            Http::redirect(Auth::allows($user, 'audit.read') ? '/m/audit_logs' : '/profile');
        }
        return ['dashboard', ['title' => 'Dashboard'] + Dashboard::data($user)];
    }
    if (in_array($path, ['/statistics', '/analysis'], true) && !$post) {
        $name = $path === '/statistics' ? 'Statistik Pemeriksaan' : 'Analisis Temuan';
        return ['dashboard', ['title' => $name, 'reporting' => $path] + Dashboard::data($user)];
    }
    if ($path === '/system' && !$post) {
        Auth::require($user, 'system.read');
        return ['system', ['title' => 'Informasi Sistem', 'database' => query('SELECT VERSION()')->fetchColumn()]];
    }
    if ($path === '/archive' && !$post) {
        $archive = Records::view('reports', $modules['reports'], $user, true);
        $archive['title'] = 'Arsip Laporan';
        return ['records', $archive];
    }
    if (!$post && preg_match('~^/reports/(\d+)(/pdf)?$~D', $path, $matches)) {
        $document = Reports::document((int) $matches[1], $user, isset($matches[2]));
        return ['preview', ['title' => 'Pratinjau Laporan'] + $document];
    }
    if ($path === '/backup' && $post) {
        Auth::require($user, 'backup.write');
        $action = text_input($_POST, 'action');
        $id = (int) text_input($_POST, 'id');
        if ($action === 'create') {
            Backup::create((int) $user['id']);
        } elseif ($action === 'download') {
            Backup::download($id, (int) $user['id']);
        } elseif ($action === 'restore' && text_input($_POST, 'confirmation') === 'PULIHKAN') {
            Backup::restore($id, (int) $user['id']);
        } else {
            throw new Http(422, 'Konfirmasi atau tindakan backup tidak valid.');
        }
        $_SESSION['notice'] = 'Tindakan backup selesai.';
        Http::redirect('/m/backup_history');
    }
    $table = substr($path, 3);
    if (str_starts_with($path, '/m/') && isset($modules[$table])) {
        return ['records', Records::view($table, $modules[$table], $user)];
    }
    throw new Http(404, 'Halaman tidak ditemukan.');
}
