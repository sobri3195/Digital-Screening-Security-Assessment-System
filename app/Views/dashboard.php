<div class="page-heading">
    <div><p class="eyebrow">PUSKESAU SENTINEL</p><h1><?= escape($data['title']) ?></h1></div>
    <span class="status"><span class="indicator"></span> Basis data tersambung</span>
</div>
<form class="panel filter-grid" method="get">
    <label>Dari <input class="form-control" type="date" name="from" value="<?= escape($data['from']) ?>"></label>
    <label>Sampai <input class="form-control" type="date" name="to" value="<?= escape($data['to']) ?>"></label>
    <label>Bulan <input class="form-control" type="month" name="month" value="<?= escape($data['month']) ?>"></label>
    <label>Tahun <input class="form-control" name="year" type="number" min="1900" max="2200" value="<?= escape($data['year']) ?>"></label>
    <label>Periode kegiatan <select class="form-select" name="period"><option value="">Semua</option>
        <?php foreach ($data['periods'] as $period): ?><option value="<?= escape($period['id']) ?>" <?= (string) $period['id'] === $data['period'] ? 'selected' : '' ?>><?= escape($period['title']) ?></option><?php endforeach ?>
    </select></label>
    <button class="btn btn-primary"><i class="bi bi-funnel" aria-hidden="true"></i> Terapkan</button>
</form>
<?php if (!isset($data['reporting'])): ?>
<div class="metric-grid">
    <?php $metricIcons = ['calendar-event', 'clipboard2-check', 'check2-circle', 'clock', 'shield-exclamation', 'exclamation-triangle', 'file-earmark-text', 'pc-display']; $index = 0;
    foreach ($data['cards'] as $label => $value): ?>
        <section class="panel metric"><i class="bi bi-<?= $metricIcons[$index++] ?>" aria-hidden="true"></i><span><?= escape($label) ?></span><strong><?= escape(number_format($value, 0, ',', '.')) ?></strong></section>
    <?php endforeach ?>
</div>
<?php endif ?>
<div class="chart-grid">
    <?php foreach ($data['charts'] as $label => $values): ?>
        <?php if (isset($data['reporting']) && ($data['reporting'] === '/statistics') !== str_starts_with($label, 'Pemeriksaan')) { continue; } ?>
        <section class="panel chart-panel"><h2><?= escape($label) ?></h2>
            <?php if (!$values): ?><p class="empty">Belum ada data untuk filter ini.</p><?php else: ?>
                <canvas aria-label="<?= escape($label) ?>" role="img" data-chart="<?= escape(json_encode(array_reverse($values), JSON_INVALID_UTF8_SUBSTITUTE)) ?>"></canvas>
                <details><summary>Data grafik</summary><ul><?php foreach ($values as $item): ?><li><?= escape($item['label']) ?> · <?= escape($item['total']) ?></li><?php endforeach ?></ul></details>
            <?php endif ?>
        </section>
    <?php endforeach ?>
</div>
<?php if (!isset($data['reporting'])): ?>
<div class="chart-grid">
    <?php if (Sentinel\Core\Auth::allows($user, 'admin.read')): ?><section class="panel"><h2>Jadwal berikutnya</h2>
        <?php if (!$data['schedule']): ?><p class="empty">Belum ada pemeriksaan terjadwal.</p><?php endif ?>
        <ul class="activity-list"><?php foreach ($data['schedule'] as $entry): ?><li><span><?= escape($entry['title']) ?></span><time><?= escape($entry['scheduled_on']) ?></time></li><?php endforeach ?></ul>
    </section><?php endif ?>
    <?php if (Sentinel\Core\Auth::allows($user, 'audit.read')): ?><section class="panel"><h2>Aktivitas terbaru</h2>
        <?php if (!$data['events']): ?><p class="empty">Belum ada aktivitas.</p><?php endif ?>
        <ul class="activity-list"><?php foreach ($data['events'] as $entry): ?><li><span><?= escape($entry['action']) ?> · <?= escape($entry['module']) ?></span><time><?= escape($entry['created_at']) ?></time></li><?php endforeach ?></ul>
    </section><?php endif ?>
</div>
<?php endif ?>
