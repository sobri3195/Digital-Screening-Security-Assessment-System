<?php
use Sentinel\Services\Threat\{Analysis, Indicator};

require __DIR__ . '/common.php';
$scan = $data['scan'];
?>
<section class="panel spaced">
    <h2>Pemeriksaan lokal</h2>
    <p>Pencocokan memakai data yang tersimpan pada Sentinel. Hasil dapat dipengaruhi cakupan dan kesegaran sumber.</p>
    <form method="post" class="record-form" action="<?= escape($base) ?>">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <label><?= escape(['url'=>'URL HTTP/HTTPS','domain'=>'Domain','ip'=>'Alamat IPv4 atau IPv6','hash'=>'Hash MD5, SHA-1, atau SHA-256'][$data['expected']] ?? 'URL, domain, alamat IP, hash, atau CVE') ?>
            <input class="form-control" type="text" name="indicator" maxlength="2048" required autocomplete="off" spellcheck="false">
        </label>
        <button class="btn btn-primary" name="action" value="scan"><i class="bi bi-search" aria-hidden="true"></i> Periksa</button>
    </form>
</section>
<?php if ($route === 'phishing'): ?>
    <section class="panel spaced"><h2>Tindakan defensif</h2><p>Verifikasi domain resmi melalui kanal terpisah. Laporkan indikasi ke petugas keamanan informasi dan terapkan pemblokiran sesuai kewenangan. Kemiripan domain perlu ditinjau.</p></section>
<?php endif ?>
<?php if ($scan): ?>
<section class="panel spaced">
    <h2>Hasil #<?= escape($scan['id']) ?></h2>
    <p class="ti-value"><?= escape($scan['display_value']) ?></p>
    <p>Prioritas peninjauan <?= escape($scan['priority']) ?>/100 · <?= escape(Analysis::level($scan['priority'])) ?> · <?= escape($scan['rule_version']) ?></p>
    <?php if (!$scan['matches']): ?><p class="empty">Tidak ada indikator cocok dalam katalog lokal yang berlaku. Keamanan belum dapat disimpulkan.</p><?php endif ?>
    <?php if ($scan['facts']['facts']): ?><ul><?php foreach ($scan['facts']['facts'] as $fact): ?><li><?= escape($fact) ?></li><?php endforeach ?></ul><?php endif ?>
    <?php if ($scan['facts']['brand']): ?><h3>Kemiripan dengan domain rujukan</h3>
        <?php $listing($scan['facts']['brand'],['domain'=>'Domain rujukan','title'=>'Institusi','basis'=>'Dasar indikasi']); ?>
    <?php endif ?>
    <?php foreach ($scan['matches'] as $match):
        $meta = $match['metadata']; ?>
        <details class="ti-evidence"><summary><?= escape($match['basis']) ?> · <?= escape($meta['provider'] ?? $meta['cve']) ?></summary>
            <?php $details($meta,['display_value'=>'Indikator','cve'=>'CVE','provider'=>'Sumber','category'=>'Kategori','severity'=>'Keparahan','confidence'=>'Keyakinan sumber (0–100)',
                'first_seen'=>'Pertama diamati','last_seen'=>'Terakhir diamati','retrieved_at'=>'Data diambil','reference_text'=>'Rujukan','evidence_sha256'=>'SHA-256 bukti',
                'malware_family'=>'Keluarga malware','cvss'=>'CVSS','epss'=>'EPSS','epss_on'=>'Tanggal EPSS','kev_added_on'=>'Masuk KEV','kev_due_on'=>'Tenggat CISA']); ?>
            <?php if (isset($meta['evidence'])): ?><p class="ti-value"><?= escape($meta['evidence']['observed_state'] ?? '') ?> <?= escape(implode(', ', $meta['evidence']['tags'] ?? [])) ?></p><?php endif ?>
        </details>
    <?php endforeach ?>
    <details class="ti-evidence"><summary>Komponen skor prioritas</summary>
        <ul><?php foreach ($scan['facts']['priority_reasons'] as $label => $points): ?><li><?= escape(str_replace('_',' ',$label)) ?> · <?= escape($points) ?></li><?php endforeach ?></ul>
    </details>
    <?php if ($can('report.generate')): ?>
        <form method="post" action="/threat/reports" class="actions"><input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <input type="hidden" name="scan_id" value="<?= escape($scan['id']) ?>">
            <input type="hidden" name="kind" value="<?= escape(['ipv4'=>'ip','ipv6'=>'ip','md5'=>'malware','sha1'=>'malware','sha256'=>'malware','cve'=>'vulnerability'][$scan['kind']] ?? $scan['kind']) ?>">
            <button class="btn btn-outline-secondary" name="action" value="create">Buat laporan</button>
        </form>
    <?php endif ?>
</section>
<?php endif ?>
<?php if ($route === 'brand'): ?>
<section class="panel spaced"><h2>Domain resmi yang dirujuk</h2>
    <?php $rows = array_map(static function (array $domain): array { $domain['domain'] = Indicator::defang($domain['domain'],'domain'); return $domain; }, $data['domains']);
    $listing($rows,['domain'=>'Domain','title'=>'Nama','active'=>'Aktif (1/0)']); ?>
    <?php if ($can('settings.manage')): ?>
        <form method="post" action="<?= escape($base) ?>" class="record-form">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <?php $input('Domain resmi','domain','text','',true); $input('Nama institusi atau layanan','title','text','',true); $select('Aktif (1/0)','active',['1','0'],'1'); ?>
            <button class="btn btn-primary" name="action" value="domain">Simpan domain rujukan</button>
        </form>
    <?php endif ?>
</section>
<?php endif ?>
<section class="panel"><h2>Riwayat pemeriksaan saya</h2>
    <?php $listing($data['history'],['display_value'=>'Indikator','kind'=>'Tipe','priority'=>'Prioritas','searched_at'=>'Waktu'], static function ($row) use ($base): void { ?>
        <a href="<?= escape($base) ?>?id=<?= escape($row['id']) ?>">Buka</a>
    <?php }); ?>
</section>
