<div class="page-heading"><h1>Informasi Sistem</h1></div>
<section class="panel">
    <h2>Runtime</h2>
    <dl class="detail-grid"><dt>Versi aplikasi</dt><dd>1.0.0</dd>
    <dt>PHP</dt><dd><?= escape(PHP_VERSION) ?></dd><dt>Database</dt><dd><?= escape($data['database']) ?></dd>
    <dt>Zona waktu</dt><dd><?= escape(date_default_timezone_get()) ?></dd>
    <dt>Generator PDF</dt><dd><?= class_exists(Dompdf\Dompdf::class) ? 'Terpasang' : 'Belum terpasang' ?></dd></dl>
    <h2>Integrasi eksternal</h2>
    <dl class="detail-grid">
    <?php foreach (['Intelijen ancaman URL', 'Advisori keamanan siber', 'Analisis malware', 'AI lokal', 'Perangkat desktop', 'Antivirus lokal'] as $integration): ?>
        <dt><?= escape($integration) ?></dt><dd>Belum terintegrasi</dd>
    <?php endforeach ?>
    </dl>
</section>
