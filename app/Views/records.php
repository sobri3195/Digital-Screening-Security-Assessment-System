<?php
use Sentinel\Controllers\Records;
use Sentinel\Core\Auth;

$table = $data['table'];
$fields = $data['fields'];
$record = $data['record'];
$special = $data['special'];
$write = $data['write'];
$archive = $data['archive'];
$base = $archive ? '/archive' : '/m/' . $table;
$isBackup = $special === 'backup';
$csrf = escape(Auth::csrf());
$secret = $special === 'clients' ? ($_SESSION['client_secret'] ?? null) : null;
if ($secret !== null) {
    unset($_SESSION['client_secret']);
}
$columns = array_slice($fields, 0, 4, true);
?>
<div class="page-heading">
    <div><p class="eyebrow"><?= escape($data['module'][1]) ?></p><h1><?= escape($archive ? 'Arsip Laporan' : $data['title']) ?></h1></div>
    <?php if (($data['module']['csv'] ?? false) || $special === 'url'): ?>
        <a class="btn btn-outline-secondary" href="<?= escape($base . '?' . http_build_query(['export' => 'csv', 'q' => $data['search'], 'state' => $data['state']])) ?>"><i class="bi bi-download"></i> Ekspor CSV</a>
    <?php endif ?>
</div>
<?php if ($secret): ?>
    <section class="notice" role="status"><strong>ID klien <?= escape($secret['id']) ?></strong><p>Salin rahasia ini sekarang. Rahasia ditampilkan sekali.</p><code><?= escape($secret['secret']) ?></code></section>
<?php endif ?>
<form class="panel filter-grid compact" method="get" action="<?= escape($base) ?>">
    <label>Pencarian <input class="form-control" type="search" name="q" value="<?= escape($data['search']) ?>" maxlength="160"></label>
    <?php if (isset($fields['state']) && str_starts_with(explode(':', $fields['state'])[1] ?? '', 'select')): ?>
    <label>Status <select class="form-select" name="state"><option value="">Semua</option>
        <?php foreach (explode(',', explode(':', $fields['state'])[2]) as $state): ?>
            <option <?= $state === $data['state'] ? 'selected' : '' ?>><?= escape($state) ?></option>
        <?php endforeach ?>
    </select></label>
    <?php endif ?>
    <button class="btn btn-primary"><i class="bi bi-search"></i> Cari</button>
</form>
<?php if ($write && $table === 'system_settings'): ?>
<section class="panel spaced"><h2>Logo institusi</h2>
    <form action="/institution-logo" method="post" enctype="multipart/form-data" class="record-form">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <label>Logo PNG atau JPEG yang telah diotorisasi <input class="form-control" type="file" name="logo" accept="image/png,image/jpeg" required></label>
        <button class="btn btn-primary">Perbarui logo</button>
    </form>
    <p>Gunakan kunci <code>institution_name</code> untuk mengubah nama pada kop laporan.</p>
</section>
<?php endif ?>
<?php if ($write && $isBackup): ?>
    <section class="panel spaced"><h2>Backup terenkripsi</h2>
        <form action="/backup" method="post"><input type="hidden" name="_csrf" value="<?= $csrf ?>"><button class="btn btn-primary" name="action" value="create">Buat backup</button></form>
        <?php if ($record): ?>
        <form action="/backup" method="post" class="record-form">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($record['id']) ?>">
            <button class="btn btn-outline-secondary" name="action" value="download">Unduh backup <?= escape($record['id']) ?></button>
            <label>Ketik PULIHKAN untuk mengganti data aplikasi dengan isi backup ini <input name="confirmation" class="form-control" autocomplete="off"></label>
            <button class="btn btn-outline-danger" name="action" value="restore">Pulihkan backup</button>
        </form>
        <?php endif ?>
    </section>
<?php elseif ($write && !in_array($special, ['readonly'], true)): ?>
    <details class="panel spaced" <?= $record ? 'open' : '' ?>>
        <summary><?= escape($special === 'url' ? 'Periksa URL' : ($special === 'file' ? 'Periksa file' : ($record ? 'Ubah data' : 'Tambah data'))) ?></summary>
        <?php if ($special === 'url'): ?><p>Pemeriksaan statis. Indikator perlu ditinjau dan tidak menyatakan bahwa URL berbahaya.</p><?php endif ?>
        <?php if ($special === 'file'): ?><p>File disimpan secara privat selama 30 hari. Ukuran maksimum 10 MiB.</p><?php endif ?>
        <form method="post" enctype="multipart/form-data" action="<?= escape($base) ?>" class="record-form">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <input type="hidden" name="id" value="<?= escape($record['id'] ?? '') ?>">
            <?php if ($special === 'file'): ?>
                <label>File teknis <input class="form-control" type="file" name="file" required></label>
            <?php elseif ($special === 'url'): ?>
                <label>URL <input class="form-control" type="url" name="title" maxlength="2048" required autocomplete="off" placeholder="https://example.org"></label>
            <?php else: foreach ($fields as $key => $definition):
                [$label, $type, $options] = array_pad(explode(':', $definition), 3, '');
                $value = (string) ($record[$key] ?? '');
                $required = in_array($key, ['title', 'code', 'username', 'active', 'starts_on', 'ends_on', 'activity_year'], true)
                    || ($key === 'asset_id' && $special === 'checklist'); ?>
                <label><?= escape($label) ?>
                <?php if ($type === 'long'): ?>
                    <textarea class="form-control" rows="3" name="<?= escape($key) ?>" maxlength="10000"><?= escape($value) ?></textarea>
                <?php elseif ($type === 'select' || $type === 'ref'): ?>
                    <select class="form-select" name="<?= escape($key) ?>" <?= $required ? 'required' : '' ?>>
                        <option value="">Pilih</option>
                        <?php $choices = $type === 'ref' ? $data['references'][$key] : array_combine($opts = explode(',', $options), $opts);
                        foreach ($choices as $choice => $choiceLabel): ?>
                            <option value="<?= escape($choice) ?>" <?= $value === (string) $choice ? 'selected' : '' ?>><?= escape(str_replace('_', ' ', $choiceLabel)) ?></option>
                        <?php endforeach ?>
                    </select>
                <?php else: ?>
                    <input class="form-control" type="<?= escape(in_array($type, ['date', 'number'], true) ? $type : 'text') ?>" name="<?= escape($key) ?>" value="<?= escape($value) ?>"
                        <?= $type === 'number' ? 'min="0"' : '' ?> <?= $required ? 'required' : '' ?> maxlength="<?= $key === 'code' || $key === 'username' ? 100 : ($key === 'title' ? 160 : 255) ?>">
                <?php endif ?>
                </label>
            <?php endforeach; endif ?>
            <?php if ($special === 'users'): ?><label><?= $record ? 'Kata sandi baru (opsional)' : 'Kata sandi awal' ?><input type="password" class="form-control" name="password" autocomplete="new-password" minlength="12" <?= $record ? '' : 'required' ?>></label><?php endif ?>
            <?php if ($special === 'users' || $special === 'roles'): ?>
                <fieldset><legend><?= $special === 'users' ? 'Role' : 'Izin' ?></legend>
                <?php foreach ($data['extras']['options'] as $value => $label): ?>
                    <label class="choice"><input type="checkbox" name="grants[]" value="<?= escape($value) ?>" <?= in_array((string) $value, array_map('strval', $data['extras']['selected']), true) ? 'checked' : '' ?>> <?= escape($label) ?></label>
                <?php endforeach ?>
                </fieldset>
            <?php endif ?>
            <?php if ($special === 'checklist'): ?>
                <fieldset><legend>Indikator keamanan aset</legend>
                <?php foreach ($data['extras']['items'] as $item): ?>
                    <label><?= escape($item['title']) ?><select class="form-select" name="check[<?= escape($item['id']) ?>]">
                        <?php foreach (Records::CHECK_STATES as $state): ?><option value="<?= escape($state) ?>" <?= ($data['extras']['results'][$item['id']] ?? 'belum_diperiksa') === $state ? 'selected' : '' ?>><?= escape(str_replace('_', ' ', $state)) ?></option><?php endforeach ?>
                    </select></label>
                <?php endforeach ?>
                </fieldset>
            <?php endif ?>
            <?php if (isset($data['extras']['history'])): ?><label>Catatan riwayat baru <textarea class="form-control" name="history_note" maxlength="10000"></textarea></label><?php endif ?>
            <div class="actions">
                <button class="btn btn-primary" name="action" value="simpan"><?= in_array($special, ['url', 'file'], true) ? 'Periksa' : 'Simpan' ?></button>
                <?php if ($record && $special === 'clients'): ?><button class="btn btn-outline-warning" name="action" value="rotasi">Rotasi rahasia klien</button><?php endif ?>
                <?php if ($record && in_array($table, ['institutional_assets', 'education', 'inspection_schedules', 'activity_periods'], true)): ?>
                    <button class="btn btn-outline-danger" name="action" value="hapus" data-confirm="Hapus entri ini?" formnovalidate>Hapus</button>
                <?php endif ?>
            </div>
        </form>
    </details>
    <?php if ($data['module']['csv'] ?? false): ?>
        <details class="panel spaced"><summary>Impor CSV</summary>
        <form method="post" enctype="multipart/form-data" class="record-form" action="<?= escape($base) ?>">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>"><label>CSV dengan tajuk sesuai ekspor <input class="form-control" type="file" name="csv" accept=".csv,text/csv" required></label>
            <button name="action" value="import" class="btn btn-primary">Impor</button>
        </form></details>
    <?php endif ?>
<?php endif ?>
<?php if ($record): ?>
<section class="panel spaced"><h2>Rincian · <?= escape($record['id']) ?></h2>
    <dl class="detail-grid">
    <?php foreach ($fields as $key => $definition): ?>
        <dt><?= escape(explode(':', $definition)[0]) ?></dt><dd><?= escape($data['references'][$key][$record[$key]] ?? $record[$key] ?? '—') ?></dd>
    <?php endforeach ?>
    </dl>
    <?php if ($special === 'checklist'): ?><h3>Hasil checklist</h3><dl class="detail-grid">
        <?php foreach ($data['extras']['items'] as $item): ?><dt><?= escape($item['title']) ?></dt>
            <dd><?= escape(str_replace('_', ' ', $data['extras']['results'][$item['id']] ?? 'belum_diperiksa')) ?></dd>
        <?php endforeach ?>
    </dl><?php endif ?>
    <?php if ($special === 'file' && Auth::allows($user, 'threat.scan.execute') && !empty($record['sha256'])): ?>
        <form method="post" action="/threat/hashes" class="actions">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <input type="hidden" name="indicator" value="<?= escape($record['sha256']) ?>">
            <button class="btn btn-outline-secondary" name="action" value="scan">Periksa SHA-256 pada katalog lokal</button>
        </form>
    <?php endif ?>
    <?php if ($special === 'report'): ?><a class="btn btn-outline-secondary" href="/reports/<?= escape($record['id']) ?>">Pratinjau laporan</a><?php endif ?>
    <?php if (isset($data['extras']['history'])): ?><h3>Riwayat</h3><ul class="activity-list">
        <?php foreach ($data['extras']['history'] as $event): ?><li><span><?= escape($event['notes']) ?></span><time><?= escape($event['created_at']) ?></time></li><?php endforeach ?>
    </ul><?php endif ?>
</section>
<?php endif ?>
<section class="panel">
    <div class="table-heading"><h2>Daftar data</h2><span><?= escape($data['total']) ?> entri</span></div>
    <?php if (!$data['rows']): ?><p class="empty">Belum ada data yang cocok.</p><?php else: ?>
    <div class="table-responsive"><table class="table align-middle" <?= count($data['rows']) > 1 ? 'data-sort-page' : '' ?>>
        <caption class="visually-hidden">Pengurutan berlaku pada halaman hasil yang sedang ditampilkan.</caption>
        <thead><tr><?php foreach ($columns as $definition): ?><th scope="col"><?= escape(explode(':', $definition)[0]) ?></th><?php endforeach ?><th scope="col">Waktu dibuat</th><th scope="col">Rincian</th></tr></thead>
        <tbody><?php foreach ($data['rows'] as $row): ?><tr>
            <?php foreach ($columns as $key => $unused): ?>
                <td><?= escape(mb_strimwidth((string) ($data['references'][$key][$row[$key]] ?? $row[$key] ?? '—'), 0, 85, '…')) ?></td>
            <?php endforeach ?>
            <td class="timestamp"><?= escape($row['created_at']) ?></td>
            <td><a href="<?= escape($base . '?' . http_build_query(['id' => $row['id'], 'page' => $data['page'], 'q' => $data['search'], 'state' => $data['state']])) ?>">Buka</a></td>
        </tr><?php endforeach ?></tbody>
    </table></div>
    <?php endif ?>
    <?php if ($data['page'] > 1 || $data['page'] * 20 < $data['total']): ?>
    <nav class="actions" aria-label="Halaman hasil">
        <?php foreach ([-1 => 'Sebelumnya', 1 => 'Berikutnya'] as $offset => $label):
            $page = $data['page'] + $offset;
            if ($page < 1 || ($offset > 0 && ($page - 1) * 20 >= $data['total'])) { continue; } ?>
            <a class="btn btn-outline-secondary" href="<?= escape($base . '?' . http_build_query(['page' => $page, 'q' => $data['search'], 'state' => $data['state']])) ?>"><?= escape($label) ?></a>
        <?php endforeach ?>
    </nav>
    <?php endif ?>
</section>
