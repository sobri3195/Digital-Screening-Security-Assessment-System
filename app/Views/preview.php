<div class="page-heading no-print">
    <h1>Pratinjau Laporan</h1>
    <div class="actions">
        <button id="print" type="button" class="btn btn-outline-secondary">Cetak</button>
        <a class="btn btn-primary" href="<?= escape($data['pdf_url'] ?? '/reports/' . $data['report']['id'] . '/pdf') ?>">Unduh PDF</a>
    </div>
</div>
<?php
$report = $data['report'];
$signatures = $data['signatures'];
$logo = $data['logo'];
$results = $data['results'];
$institution = $data['institution'];
$documentTitle = $data['documentTitle'] ?? null;
require BASE . '/app/Views/document.php';
