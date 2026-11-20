<?php if ($download ?? false): ?><!doctype html><html lang="id"><meta charset="utf-8"><style>
body { font-family: DejaVu Sans, sans-serif; font-size: 10pt; color: #162235; }
.document { padding: 22pt; } .watermark { text-align: right; color: #7c8494; font-size: 9pt; }
table { width: 100%; border-collapse: collapse; } th,td { border-bottom: 1px solid #ccc; padding: 8pt; text-align: left; }
p { white-space: pre-wrap; overflow-wrap: break-word; }
</style><body><?php endif ?>
<article class="document">
    <p class="watermark">DOKUMEN INTERNAL</p>
    <header><?php if ($logo): ?><img src="<?= escape($logo) ?>" alt="Logo institusi" width="64"><?php endif ?><strong><?= escape($institution) ?></strong><p>Sistem Penilaian Keamanan Digital</p></header>
    <h2><?= escape($report['title']) ?></h2>
    <table>
        <tr><th scope="row">Nomor laporan</th><td><?= escape($report['code']) ?></td></tr>
        <tr><th scope="row">Jenis</th><td><?= escape($report['source']) ?></td></tr>
        <tr><th scope="row">Tanggal pemeriksaan</th><td><?= escape($report['inspected_on']) ?></td></tr>
        <tr><th scope="row">Petugas</th><td><?= escape($report['officer']) ?></td></tr>
        <tr><th scope="row">Status</th><td><?= escape($report['state']) ?></td></tr>
        <?php if (!empty($report['revision_of'])): ?>
            <tr><th scope="row">Revisi dari</th><td><?= escape($report['revision_code'] ?? $report['revision_of']) ?></td></tr>
            <tr><th scope="row">Alasan revisi</th><td><?= escape($report['revision_reason']) ?></td></tr>
        <?php endif ?>
    </table>
    <?php if (!empty($report['legacy_snapshot'])): ?><p>Dokumen lama. Metadata yang dapat dipulihkan dibekukan saat migrasi.</p><?php endif ?>
    <h3>Ringkasan hasil</h3><p><?= escape($report['notes']) ?></p>
    <h3>Tabel hasil pemeriksaan</h3>
    <?php if (!$results): ?><p>Belum ada data pemeriksaan untuk jenis dan tanggal ini.</p><?php else: ?>
    <table><thead><tr><th>Judul</th><th>Referensi / jumlah</th><th>Status / mulai</th><th>Tanggal</th></tr></thead>
    <tbody><?php foreach ($results as $entry): ?><tr>
        <?php foreach ($entry as $key => $value): ?><td><?= escape($value) ?></td><?php endforeach ?>
    </tr><?php endforeach ?></tbody></table>
    <?php endif ?>
    <h3>Bukti teknis</h3><p><?= escape($report['evidence']) ?></p>
    <h3>Rekomendasi</h3><p><?= escape($report['mitigation']) ?></p>
    <h3>Persetujuan</h3>
    <?php if (!$signatures): ?><p>Belum ada persetujuan.</p><?php endif ?>
    <?php foreach ($signatures as $signature): ?><p><?= escape($signature['title']) ?> · <?= escape($signature['created_at']) ?></p><?php endforeach ?>
</article>
<?php if ($download ?? false): ?></body></html><?php endif ?>
