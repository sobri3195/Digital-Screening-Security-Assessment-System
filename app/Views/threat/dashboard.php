<?php require __DIR__ . '/common.php'; ?>
<form class="panel filter-grid" method="get">
    <?php $input('Dari','from','date',text_input($_GET,'from')); $input('Sampai','to','date',text_input($_GET,'to'));
    $field('Tipe','kind',array_slice(Sentinel\Services\Threat\Indicator::KINDS,0,-1)); $field('Sumber','source',array_keys((require BASE . '/config/threat.php')['providers']));
    $field('Status observasi','state',['active','expired']); $field('Keparahan','severity',Sentinel\Services\Threat\Store::SEVERITIES); ?>
    <button class="btn btn-primary">Terapkan filter</button>
</form>
<h2>Observasi indikator</h2>
<div class="metric-grid"><?php foreach ($data['cards'] as $label => $count): ?>
    <section class="panel metric"><span><?= escape($label) ?></span><strong><?= escape($count) ?></strong></section>
<?php endforeach ?></div>
<h2>Ringkasan seluruh katalog</h2>
<div class="metric-grid"><?php foreach ($data['global'] as $label => $count): ?>
    <section class="panel metric"><span><?= escape($label) ?></span><strong><?= escape($count) ?></strong></section>
<?php endforeach ?></div>
<div class="chart-grid"><?php foreach ($data['charts'] as $label => $rows): ?>
    <section class="panel chart-panel"><h2><?= escape($label) ?></h2>
        <?php if (!$rows): ?><p class="empty">Belum ada data.</p><?php else: ?>
        <canvas aria-label="<?= escape($label) ?>" role="img" data-chart="<?= escape(json_encode(array_reverse($rows))) ?>"></canvas>
        <details><summary>Data grafik</summary><ul><?php foreach ($rows as $row): ?><li><?= escape($row['label']) ?> · <?= escape((string) $row['total']) ?></li><?php endforeach ?></ul></details>
        <?php endif ?>
    </section>
<?php endforeach ?></div>
<div class="chart-grid">
    <section class="panel"><h2>Observasi terbaru</h2><?php $listing($data['latest'],['display_value'=>'Indikator','provider'=>'Sumber','retrieved_at'=>'Diambil'],
        $can('indicator.view') ? static function ($row): void { ?><a href="/threat/indicators?id=<?= escape($row['id']) ?>">Rincian</a><?php } : null); ?></section>
    <section class="panel"><h2>Kerentanan prioritas</h2><?php $listing($data['priority_cves'],['cve'=>'CVE','cvss'=>'CVSS','epss'=>'EPSS','kev_added_on'=>'KEV'],
        $can('vulnerability.view') ? static function ($row): void { ?><a href="/threat/vulnerabilities?id=<?= escape($row['id']) ?>">Rincian</a><?php } : null); ?></section>
</div>
