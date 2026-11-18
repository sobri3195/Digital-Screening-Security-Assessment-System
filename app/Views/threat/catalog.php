<?php
use Sentinel\Services\Threat\{Analysis, Indicator, IntelligenceReports, Store};

require __DIR__ . '/common.php';
$isIoc = in_array($route,['indicators','malware'],true);
?>
<?php if ($isIoc || in_array($route,['vulnerabilities','advisories','alerts'],true)): ?>
<form class="panel filter-grid" method="get">
    <?php if ($route !== 'alerts'): $input('Pencarian','q','search',text_input($_GET,'q')); endif;
    $field('Keparahan','severity',Store::SEVERITIES);
    if ($isIoc) {
        $field('Tipe','kind',array_slice(Indicator::KINDS, 0, -1));
        $field('Sumber','source',array_keys((require BASE . '/config/threat.php')['providers']));
        $field('Status','state',['active','expired']);
    } elseif ($route === 'vulnerabilities') {
        $field('Status','state',['kev']);
    } elseif ($route === 'advisories') {
        $field('Sektor','sector',['healthcare']);
        $field('Status','state',['baru','ditinjau','mitigasi','arsip']);
    } else {
        $field('Status','status',['baru','dibaca','dikonfirmasi','selesai']);
    }
    if ($route !== 'alerts') {
        $input('Dari','from','date',text_input($_GET,'from')); $input('Sampai','to','date',text_input($_GET,'to'));
    } ?>
    <button class="btn btn-primary">Terapkan filter</button>
</form>
<?php endif ?>
<?php if ($route === 'indicators' && $can('indicator.manage')): ?>
    <div class="chart-grid">
        <details class="panel"><summary>Catat observasi</summary>
            <form method="post" class="record-form">
                <input type="hidden" name="_csrf" value="<?= $csrf ?>">
                <?php $input('Indikator','indicator','text','',true); $select('Kategori','category',Store::CATEGORIES,'unknown');
                $select('Keparahan','severity',Store::SEVERITIES,'unknown'); $input('Keyakinan sumber (0–100)','confidence','number');
                $input('Tanggal kedaluwarsa','expires','date'); $input('Referensi HTTPS atau HTTP','reference','text'); ?>
                <button class="btn btn-primary" name="action" value="manual">Simpan observasi</button>
            </form>
        </details>
        <details class="panel"><summary>Impor dan ekspor offline</summary>
            <form method="post" enctype="multipart/form-data" class="record-form">
                <input type="hidden" name="_csrf" value="<?= $csrf ?>">
                <?php $select('Format paket','format',['csv','json']); ?>
                <label>File (maks. 4 MiB)<input type="file" name="package" class="form-control" accept=".csv,.json" required></label>
                <button class="btn btn-primary" name="action" value="import">Impor</button>
            </form>
            <div class="actions"><a href="?export=json">Unduh paket JSON</a><a href="?export=csv">Ekspor CSV</a></div>
        </details>
    </div>
<?php endif ?>
<?php if ($route === 'advisories' && $can('indicator.manage')): ?>
<details class="panel spaced"><summary>Catat advisori</summary>
    <form method="post" class="record-form">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <?php $select('Organisasi penerbit','provider',['bssn','kemkes','manual']); $input('Judul','title','text','',true);
        $input('Dipublikasikan','published','date'); $select('Keparahan','severity',Store::SEVERITIES,'unknown');
        $input('Jenis ancaman','category'); $input('Produk terdampak','product'); $input('CVE','cve'); $input('URL publikasi asli','reference'); ?>
        <label>Ringkasan<textarea class="form-control" name="summary" required maxlength="8000"></textarea></label>
        <label>Mitigasi<textarea class="form-control" name="mitigation" maxlength="8000"></textarea></label>
        <label class="choice"><input type="checkbox" name="healthcare" value="1"> Sektor kesehatan</label>
        <button class="btn btn-primary" name="action" value="add">Simpan advisori</button>
    </form>
</details>
<details class="panel spaced"><summary>Impor salinan advisori resmi</summary>
    <form method="post" enctype="multipart/form-data" class="record-form">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <?php $select('Organisasi','provider',['bssn','kemkes']); $select('Format','format',['rss','html']); ?>
        <label>Salinan RSS, Atom, atau HTML yang diotorisasi <input type="file" name="advisory" class="form-control" required></label>
        <button class="btn btn-primary" name="action" value="import">Impor advisori</button>
    </form>
</details>
<?php endif ?>
<?php if ($route === 'reports' && $can('report.generate')): ?>
<section class="panel spaced"><h2>Buat laporan dari katalog lokal</h2>
    <form method="post" class="record-form"><input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <label>Jenis laporan<select name="kind" class="form-select">
            <?php foreach (IntelligenceReports::TITLES as $key => $label): ?><option value="<?= escape($key) ?>"><?= escape($label) ?></option><?php endforeach ?>
        </select></label>
        <button class="btn btn-primary" name="action" value="create">Buat laporan</button>
    </form>
</section>
<?php endif ?>
<?php if ($detail = $data['detail'] ?? null): ?>
    <section class="panel spaced">
        <h2><?= escape($detail['title'] ?? $detail['cve'] ?? $detail['display_value'] ?? 'Rincian job') ?></h2>
        <?php require __DIR__ . '/detail.php'; ?>
    </section>
<?php endif ?>
<section class="panel"><h2>Daftar hasil</h2>
<?php
$rows = array_slice($data['rows'], 0, 25);
$columns = match ($route) {
    'indicators','malware' => ['display_value'=>'Indikator','kind'=>'Tipe','provider'=>'Sumber','category'=>'Kategori','family'=>'Keluarga','retrieved_at'=>'Diambil'],
    'vulnerabilities' => ['cve'=>'CVE','vendor'=>'Vendor','product'=>'Produk','cvss'=>'CVSS','epss'=>'EPSS','severity'=>'Keparahan','kev_added_on'=>'Masuk KEV'],
    'advisories' => ['title'=>'Judul','publisher'=>'Penerbit','published_on'=>'Tanggal','severity'=>'Keparahan','cve'=>'CVE','state'=>'Status'],
    'monitor' => ['provider'=>'Sumber','action'=>'Jenis','state'=>'Status','received'=>'Diterima','unchanged'=>'Tidak berubah','rejected'=>'Ditolak','last_message'=>'Hasil','updated_at'=>'Waktu'],
    'alerts' => ['title'=>'Alert','category'=>'Kategori','severity'=>'Keparahan','status'=>'Status','last_seen'=>'Terakhir diamati'],
    'reports' => ['code'=>'Nomor','title'=>'Judul','created_at'=>'Dibuat','approved_at'=>'Disetujui'],
};
$listing($rows,$columns,static function ($row) use ($route, $base, $csrf, $can, $select, $input): void {
    if ($route === 'alerts'): ?>
        <details><summary>Tindak lanjut</summary>
            <form method="post" action="<?= escape($base) ?>" class="record-form">
                <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($row['id']) ?>">
                <?php $select('Status','status',['baru','dibaca','dikonfirmasi','selesai'],$row['status']); $input('ID petugas','assignee','number',$row['assignee_id']); ?>
                <button class="btn btn-primary" name="action" value="status">Simpan</button>
            </form>
        </details>
    <?php elseif ($route === 'reports'): ?>
        <a href="/threat/reports/<?= escape($row['id']) ?>">Pratinjau</a>
        <?php if ($can('report.approve') && !$row['approved_at']): ?>
            <form method="post" class="actions">
                <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($row['id']) ?>">
                <button class="btn btn-outline-secondary btn-sm" name="action" value="approve">Setujui</button>
            </form>
        <?php endif ?>
    <?php else: ?><a href="<?= escape($base) ?>?id=<?= escape($row['id']) ?>">Rincian</a><?php endif;
});
if (count($data['rows']) > 25) {
    $args = $_GET;
    unset($args['id']);
    $args['after'] = end($rows)['id']; ?>
    <a class="btn btn-outline-secondary" href="<?= escape($base . '?' . http_build_query($args)) ?>">Berikutnya</a>
<?php } ?>
<?php if (isset($_GET['after'])): ?><a class="btn btn-outline-secondary" href="<?= escape($base . '?' . http_build_query(array_diff_key($_GET,['after'=>true,'id'=>true]))) ?>">Halaman pertama</a><?php endif ?>
</section>
