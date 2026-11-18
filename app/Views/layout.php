<?php
use Sentinel\Core\Auth;

$title = $data['title'];
$logo = $user && $template !== 'error' ? Sentinel\Services\Branding::dataUri() : '';
$notice = $_SESSION['notice'] ?? null;
unset($_SESSION['notice']);
$labels = ['Utama', 'Administrasi', 'Keamanan Digital', 'Pelaporan', 'Sistem'];
$icons = ['speedometer2', 'clipboard2-check', 'shield-check', 'bar-chart', 'gear'];
$links = [
    'Utama' => [['Dashboard', '/', 'dashboard.read']],
    'Pelaporan' => [
        ['Statistik Pemeriksaan', '/statistics', 'dashboard.read'],
        ['Analisis Temuan', '/analysis', 'dashboard.read'],
        ['Arsip Laporan', '/archive', 'report.read'],
    ],
    'Sistem' => [['Informasi Sistem', '/system', 'system.read']],
];
foreach ($modules as $table => $module) {
    [$label, $group, $permission] = $module;
    $links[$group][] = [$label, '/m/' . $table, $permission . '.read'];
}
?><!doctype html>
<html lang="id" data-bs-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="icon" href="data:,">
    <title><?= escape($title) ?> · PUSKESAU SENTINEL</title>
    <link rel="stylesheet" href="/assets/vendor/bootstrap.min.css">
    <link rel="stylesheet" href="/assets/vendor/bootstrap-icons.css">
    <link rel="stylesheet" href="/assets/css/sentinel.css">
    <script defer src="/assets/vendor/bootstrap.bundle.min.js"></script>
    <?php if ($template === 'records'): ?>
    <link rel="stylesheet" href="/assets/vendor/sweetalert2.css">
    <script defer src="/assets/vendor/jquery.js"></script>
    <script defer src="/assets/vendor/datatables.js"></script>
    <script defer src="/assets/vendor/sweetalert2.js"></script>
    <?php endif ?>
    <script defer src="/assets/js/sentinel.js"></script>
    <?php if ($template === 'dashboard'): ?><script defer src="/assets/vendor/chart.js"></script><?php endif ?>
</head>
<body class="<?= $user ? 'application' : 'guest' ?>">
<?php if ($user): ?>
    <aside id="sidebar" class="sidebar" aria-label="Navigasi utama">
        <a class="brand" href="/"><span class="insignia"><?php if ($logo): ?><img class="brand-logo" src="/institution-logo" alt=""><?php else: ?><i class="bi bi-shield-lock" aria-hidden="true"></i><?php endif ?></span><span>PUSKESAU<small>SENTINEL</small></span></a>
        <nav>
            <?php foreach ($labels as $i => $group):
                $visible = array_filter($links[$group] ?? [], static fn ($link) => Auth::allows($user, $link[2])
                    || ($link[1] === '/m/reports' && Auth::allows($user, 'report.approved')));
                if (!$visible) { continue; } ?>
                <p class="nav-label"><i class="bi bi-<?= escape($icons[$i]) ?>" aria-hidden="true"></i><?= escape($group) ?></p>
                <?php foreach ($visible as [$label, $href]): ?>
                    <a href="<?= escape($href) ?>" <?= $path === $href ? 'aria-current="page"' : '' ?>><?= escape($label) ?></a>
                <?php endforeach ?>
            <?php endforeach ?>
        </nav>
        <div class="sidebar-footer"><span class="indicator"></span> INTRANET · v1.0.0</div>
    </aside>
    <button type="button" class="sidebar-backdrop" aria-label="Tutup menu"></button>
    <div class="workspace">
        <header class="topbar">
            <div class="top-tools">
                <button type="button" id="nav-toggle" class="icon-button" title="Menu" aria-label="Menu" aria-controls="sidebar" aria-expanded="true"><i class="bi bi-list"></i></button>
                <span class="breadcrumb-text">Sentinel <i class="bi bi-chevron-right"></i> <?= escape($title) ?></span>
            </div>
            <div class="top-tools">
                <button type="button" id="fullscreen" class="icon-button" title="Layar penuh" aria-label="Layar penuh"><i class="bi bi-arrows-fullscreen"></i></button>
                <button type="button" class="icon-button theme-toggle" title="Ubah tema" aria-label="Ubah tema"><i class="bi bi-circle-half"></i></button>
                <a class="profile-link" href="/profile"><i class="bi bi-person-circle"></i> <span><?= escape($user['title']) ?></span></a>
                <form method="post" action="/logout"><input type="hidden" name="_csrf" value="<?= escape(Auth::csrf()) ?>"><button class="icon-button" title="Keluar" aria-label="Keluar"><i class="bi bi-box-arrow-right"></i></button></form>
            </div>
        </header>
    <?php endif ?>
    <main id="main" class="main-content">
        <?php if ($notice): ?><div class="notice" role="status"><i class="bi bi-check-circle"></i> <?= escape($notice) ?></div><?php endif ?>
        <?php require BASE . '/app/Views/' . $template . '.php'; ?>
    </main>
<?php if ($user): ?></div><?php endif ?>
</body>
</html>
