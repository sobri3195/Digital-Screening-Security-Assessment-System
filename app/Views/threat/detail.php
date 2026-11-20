<?php
use Sentinel\Services\Threat\{Analysis, Store};

if ($isIoc):
    foreach ($detail['sources'] as $source): ?>
        <details class="ti-evidence"><summary><?= escape($source['provider']) ?> · <?= escape($source['severity']) ?></summary>
            <?php $details($source,['category'=>'Kategori','confidence'=>'Keyakinan sumber','malware_family'=>'Keluarga malware','first_seen'=>'Pertama diamati',
                'last_seen'=>'Terakhir diamati','retrieved_at'=>'Diambil','expires_at'=>'Kedaluwarsa','verified_at'=>'Diverifikasi','reference_text'=>'Rujukan',
                'evidence_sha256'=>'SHA-256 bukti','parser_version'=>'Versi parser']); ?>
            <pre class="ti-value"><?= escape($source['evidence']) ?></pre>
            <?php if ($route === 'indicators' && ($can('finding.verify') || $can('indicator.manage'))): ?>
                <form method="post" action="<?= escape($base) ?>" class="actions">
                    <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($detail['id']) ?>">
                    <input type="hidden" name="provider" value="<?= escape($source['provider_id']) ?>">
                    <?php if ($can('finding.verify')): ?><button class="btn btn-outline-secondary" name="action" value="verify">Verifikasi bukti</button><?php endif ?>
                    <?php if ($can('indicator.manage')): ?><button class="btn btn-outline-secondary" name="action" value="expire">Arsipkan observasi</button><?php endif ?>
                </form>
            <?php endif ?>
        </details>
    <?php endforeach;
elseif ($route === 'vulnerabilities'): ?>
    <p>Prioritas teknis <?= escape(Analysis::vulnerabilityPriority($detail)['score']) ?>/100. EPSS adalah estimasi kemungkinan eksploitasi CVE, bukan bukti kompromi aset.</p>
    <?php if (\Sentinel\Core\Auth::allows($user, 'technical.read')): ?>
        <details class="ti-evidence"><summary>Insiden terkait</summary>
            <ul><?php foreach ($detail['incidents'] as $incident): ?>
                <li><a href="/m/security_incidents?id=<?= escape($incident['id']) ?>"><?= escape($incident['title']) ?></a></li>
            <?php endforeach ?></ul>
            <?php if ($can('finding.verify') && \Sentinel\Core\Auth::allows($user, 'technical.write')): ?>
                <form method="post" action="<?= escape($base) ?>" class="record-form">
                    <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($detail['id']) ?>">
                    <?php $input('ID insiden','incident','number'); ?>
                    <button class="btn btn-primary" name="action" value="link-incident">Tautkan</button>
                    <button class="btn btn-outline-secondary" name="action" value="unlink-incident">Lepas tautan</button>
                </form>
            <?php endif ?>
        </details>
    <?php endif ?>
    <?php if ($detail['kev_history']): ?>
        <details class="ti-evidence"><summary>Riwayat keanggotaan CISA KEV</summary>
            <?php $listing($detail['kev_history'], ['status'=>'Perubahan','observed_at'=>'Waktu sinkronisasi','sync_job_id'=>'Job','evidence_sha256'=>'SHA-256 bukti']); ?>
        </details>
    <?php endif ?>
    <?php $details($detail,['vendor'=>'Vendor','product'=>'Produk','description'=>'Deskripsi','cvss'=>'CVSS','cvss_vector'=>'Vektor CVSS','severity'=>'Keparahan',
        'published_at'=>'Publikasi','modified_at'=>'Diubah sumber','kev_added_on'=>'Masuk CISA KEV','kev_due_on'=>'Tenggat CISA','kev_action'=>'Tindakan dari CISA',
        'kev_ransomware'=>'Kampanye ransomware','epss'=>'Probabilitas EPSS','epss_percentile'=>'Persentil EPSS','epss_on'=>'Tanggal EPSS',
        'nvd_evidence_sha256'=>'Bukti NVD','kev_evidence_sha256'=>'Bukti CISA']); ?>
    <?php foreach (['nvd_evidence'=>'Metadata NVD','kev_evidence'=>'Metadata CISA'] as $key=>$label): if ($detail[$key]): ?>
        <details class="ti-evidence"><summary><?= escape($label) ?></summary><pre class="ti-value"><?= escape($detail[$key]) ?></pre></details>
    <?php endif; endforeach ?>
    <?php if (Sentinel\Core\Auth::allows($user,'ai.vulnerability.analyze')): ?>
        <a class="btn btn-outline-secondary" href="/ai/vulnerability?cve=<?= escape($detail['cve']) ?>">Jelaskan CVE dengan AI</a>
    <?php endif ?>
    <h3>Kandidat aset lokal</h3>
    <?php if ($can('finding.verify')): ?>
        <form method="post" action="<?= escape($base) ?>" class="actions">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($detail['id']) ?>">
            <button class="btn btn-primary" name="action" value="match">Cocokkan inventaris lokal</button>
        </form>
    <?php endif ?>
    <?php $listing($detail['assets'],['code'=>'Kode','title'=>'Aset','state'=>'Status','basis'=>'Dasar','due_on'=>'Tenggat internal'],
        !$can('finding.verify') ? null : static function ($row) use ($base,$csrf,$detail,$select,$input): void { ?>
        <details><summary>Ubah status</summary>
        <form method="post" action="<?= escape($base) ?>" class="record-form">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($detail['id']) ?>">
            <input type="hidden" name="finding" value="<?= escape($row['id']) ?>">
            <?php $select('Status','state',Store::ASSET_STATES,$row['state']); $input('Tenggat internal','due','date',$row['due_on']);
            $input('ID petugas','assignee','number',$row['assignee_id']); $input('Catatan','note','text',$row['note']); ?>
            <button class="btn btn-primary" name="action" value="asset">Simpan</button>
        </form></details>
    <?php }); ?>
<?php elseif ($route === 'advisories'): ?>
    <?php $details($detail,['publisher'=>'Organisasi','published_on'=>'Tanggal publikasi','severity'=>'Keparahan','category'=>'Jenis ancaman','product'=>'Produk','cve'=>'CVE',
        'summary'=>'Ringkasan','mitigation'=>'Mitigasi','reference_text'=>'Sumber resmi (defanged)','state'=>'Status','analyst_note'=>'Catatan petugas',
        'read_at'=>'Dibaca oleh saya','evidence_sha256'=>'SHA-256 bukti']); ?>
    <form method="post" action="<?= escape($base) ?>" class="actions">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($detail['id']) ?>">
        <button class="btn btn-outline-secondary" name="action" value="read">Tandai dibaca</button>
        <button class="btn btn-outline-secondary" name="action" value="bookmark"><?= $detail['bookmarked'] ? 'Hapus bookmark' : 'Bookmark' ?></button>
    </form>
    <?php if ($can('finding.verify')): ?>
    <form method="post" action="<?= escape($base) ?>" class="record-form">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($detail['id']) ?>">
        <?php $select('Tindak lanjut','state',['baru','ditinjau','mitigasi','arsip'],$detail['state']);
        $input('ID petugas','assignee','number',$detail['assignee_id']); $input('Catatan','note','text',$detail['analyst_note']); ?>
        <button class="btn btn-primary" name="action" value="follow">Simpan tindak lanjut</button>
    </form>
    <?php endif ?>
<?php elseif ($route === 'monitor'): ?>
    <?php $details($detail,['provider'=>'Provider','state'=>'Status','last_message'=>'Pesan','received'=>'Diterima','unchanged'=>'Tidak berubah','rejected'=>'Ditolak']); ?>
    <?php if ($detail['preview'] !== null): ?><details class="ti-evidence"><summary>Pratinjau parser</summary><pre class="ti-value"><?= escape($detail['preview']) ?></pre></details><?php endif ?>
    <?php $listing($detail['logs'],['state'=>'Status','message'=>'Peristiwa','created_at'=>'Waktu']); ?>
<?php endif ?>
