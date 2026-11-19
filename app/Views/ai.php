<?php
use Sentinel\Controllers\Ai;
use Sentinel\Core\Auth;

$section = $data['section'];
$csrf = escape(Auth::csrf());
$can = static fn(string $scope): bool => Auth::allows($user, 'ai.' . $scope);
$controls = ['firewall'=>'Firewall','antivirus'=>'Antivirus','updates'=>'Pembaruan','encryption'=>'Enkripsi','secure_boot'=>'Secure Boot','support'=>'Dukungan'];
$input = static function(string $label,string $name,string $value = '',string $kind = 'text'): void { ?>
    <label><?= escape($label) ?><input class="form-control" name="<?= escape($name) ?>" type="<?= escape($kind) ?>" value="<?= escape($value) ?>" autocomplete="off"></label>
<?php };
$select = static function(string $label,string $name,array $choices): void { ?>
    <label><?= escape($label) ?><select class="form-select" name="<?= escape($name) ?>">
        <?php foreach ($choices as $key=>$value): $key = is_int($key) ? (string)$value : $key; ?>
            <option value="<?= escape($key) ?>"><?= escape($value) ?></option>
        <?php endforeach ?>
    </select></label>
<?php };
$post = static function(string $path,string $action,array $fields,string $text) use ($csrf): void { ?>
    <form class="actions" method="post" action="<?= escape($path) ?>">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <?php foreach ($fields as $key=>$value): ?><input type="hidden" name="<?= escape($key) ?>" value="<?= escape($value) ?>"><?php endforeach ?>
        <button class="btn btn-outline-secondary" name="action" value="<?= escape($action) ?>"><?= escape($text) ?></button>
    </form>
<?php };
$list = static function(array $rows,array $columns,?callable $details=null): void { ?>
    <?php if (!$rows): ?><p class="empty">Belum ada data.</p><?php else: ?>
    <div class="table-responsive"><table class="table"><thead><tr>
        <?php foreach ($columns as $label): ?><th scope="col"><?= escape($label) ?></th><?php endforeach ?>
        <?php if ($details): ?><th scope="col">Tindakan</th><?php endif ?>
    </tr></thead><tbody>
        <?php foreach ($rows as $row): ?><tr>
            <?php foreach ($columns as $key=>$label): ?><td><?= escape(is_scalar($row[$key] ?? null) ? (string)$row[$key] : '—') ?></td><?php endforeach ?>
            <?php if ($details): ?><td><?php $details($row); ?></td><?php endif ?>
        </tr><?php endforeach ?>
    </tbody></table></div>
    <?php endif ?>
<?php };
$form = static function(string $kind, string $section) use ($input,$select,$csrf,$controls): void { ?>
    <form class="record-form" method="post" action="/ai/<?= escape($section) ?>">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="kind" value="<?= escape($kind) ?>">
        <?php if (in_array($kind,['threat','correlation'],true)): ?>
            <?php $select('Tipe','type',['domain'=>'Domain','ip'=>'Alamat IP','url'=>'Origin URL tanpa path atau query','hash'=>'Hash file','cve'=>'CVE']);
            $input('Indikator teknis','indicator'); ?>
        <?php elseif ($kind === 'vulnerability'): ?>
            <?php $input('CVE','cve',mb_substr(text_input($_GET,'cve'),0,32)); ?>
        <?php elseif ($kind === 'malware'): ?>
            <?php $input('SHA-256','sha256');
            $select('Engine','engine',['unknown','defender','clamav','yara','catalog']);
            $select('Status yang diamati','verdict',['unknown','no_indicators','review','detected','unavailable']); ?>
        <?php elseif ($kind === 'configuration'): ?>
            <?php $select('Platform','platform',['windows','android','ios','linux','network']);
            foreach ($controls as $key=>$label) $select($label,$key,['unknown'=>'Belum diketahui','pass'=>'Memenuhi','fail'=>'Perlu ditinjau','not_applicable'=>'Tidak berlaku']); ?>
        <?php elseif ($kind === 'mitigation'): ?>
            <?php $select('Kategori','category',['vulnerability','phishing','malware','configuration','education','incident','advisory']); ?>
        <?php elseif ($kind === 'education'): ?>
            <?php $select('Topik','topic',['ioc'=>'Indikator kompromi','cvss_epss'=>'CVSS dan EPSS','phishing'=>'Phishing','patching'=>'Pembaruan keamanan']); ?>
        <?php elseif ($kind === 'advisory'): ?>
            <?php $input('ID dokumen yang disetujui','document_id'); ?>
        <?php else: ?>
            <?php $select('Cakupan observasi malware','period',['current'=>'Snapshot katalog saat ini','monthly'=>'Bulan ini','annual'=>'Tahun ini']); ?>
            <p>Hitungan aset, insiden aktif, dan mitigasi memakai snapshot institusi saat tugas diajukan.</p>
        <?php endif ?>
        <button class="btn btn-primary" name="action" value="enqueue">Ajukan analisis</button>
    </form>
<?php };
?>
<div class="page-heading"><h1><?= escape($data['title']) ?></h1></div>
<?php if (isset($data['offline']) || ($section !== 'task' && !$data['configured'])): ?>
    <div class="panel empty" role="status"><?= escape($data['offline'] ?? 'AI Gateway belum dikonfigurasi.') ?></div>
<?php elseif ($section === 'dashboard'):
    $status=$data['status']; $health=$data['health']; ?>
    <div class="metric-grid">
    <?php foreach ([
        'Status AI'=>$health['status'],'Ollama'=>$health['runtime'],'Model aktif'=>$health['active_model'] ?? 'Belum dipilih',
        'Dokumen disetujui'=>$status['knowledge']['documents'],'Publikasi terbaru'=>$status['knowledge']['latest_publication'] ?? '—',
        'Token output'=>$status['performance']['tokens'] ?? '—','Rata-rata inferensi (ms)'=>$status['performance']['avg_ms'] ?? '—',
        'RAM tersedia (GiB)'=>round($status['hardware']['available_ram_bytes']/1073741824,1),
    ] as $label=>$value): ?>
        <section class="panel metric"><span><?= escape($label) ?></span><strong><?= escape((string)$value) ?></strong></section>
    <?php endforeach ?>
    </div>
    <div class="chart-grid">
        <?php foreach (['Tren tugas'=>array_reverse($status['daily']),'Distribusi status'=>$status['jobs'],'Jenis analisis'=>$status['analysis_types']] as $label=>$rows): ?>
        <section class="panel chart-panel"><h2><?= escape($label) ?></h2>
            <?php if ($rows): $chart = array_map(static fn($row) => ['label'=>$row['day'] ?? $row['state'] ?? $row['kind'],'total'=>$row['total'] ?? $row['count']],$rows); ?>
                <canvas role="img" aria-label="<?= escape($label) ?>" data-chart="<?= escape(json_encode($chart)) ?>"></canvas>
                <details><summary>Data grafik</summary><?php $list($chart,['label'=>'Periode / kategori','total'=>'Tugas']); ?></details>
            <?php else: ?><p class="empty">Belum ada aktivitas.</p><?php endif ?>
        </section>
        <?php endforeach ?>
        <section class="panel"><h2>Runtime dan sumber daya</h2>
            <p><?= escape($status['hardware']['cpu']) ?> · <?= escape($status['hardware']['platform']) ?></p>
            <p>Anomali kegagalan agregat · <?= escape($status['anomaly']['status']) ?></p>
            <?php if (isset($status['performance']['last_observed_vram_bound'])): ?><p>VRAM teramati (byte) · <?= escape((string)$status['performance']['last_observed_vram_bound']) ?></p><?php endif ?>
        </section>
    </div>
<?php elseif ($section === 'assistant' || isset(Ai::KINDS[$section])): ?>
    <p>Masukkan data teknis yang sudah disetujui. Semua hasil analisis memerlukan peninjauan petugas.</p>
    <?php if ($section === 'assistant'):
        $grants = ['threat'=>'threat.analyze','malware'=>'malware.analyze','vulnerability'=>'vulnerability.analyze','configuration'=>'configuration.analyze',
            'correlation'=>'threat.analyze','mitigation'=>'mitigation.generate','report'=>'report.generate','executive'=>'report.generate',
            'advisory'=>'threat.analyze','education'=>'threat.analyze'];
        foreach (Ai::KINDS as $kind=>$label): if ($can($grants[$kind])): ?>
        <details class="panel spaced"><summary><?= escape($label) ?></summary><?php $form($kind,$section); ?></details>
        <?php endif; endforeach;
    else: ?><section class="panel"><?php $form($section,$section); ?></section><?php endif ?>
<?php elseif ($section === 'tasks'):
    $list($data['jobs'],['id'=>'Nomor tugas','kind'=>'Jenis','state'=>'Status','error_code'=>'Kode kendala','created_at'=>'Dibuat'],
        static function($row): void { ?><a href="/ai/tasks/<?= escape($row['id']) ?>">Rincian</a><?php });
elseif ($section === 'task'):
    $task = $data['task']; $result = $task['result'] ?? null;
    $path = '/ai/tasks/' . $task['id']; ?>
    <section class="panel spaced" <?= in_array($task['state'],['pending','processing'],true) ? 'data-ai-job="' . escape($path . '/state') . '"' : '' ?>>
        <h2><?= escape(Ai::KINDS[$task['kind']] ?? $task['kind']) ?></h2>
        <p>Status · <strong data-ai-state><?= escape($task['state']) ?></strong></p>
        <?php if ($task['error_code']): ?><p role="alert"><?= escape($task['error_code']) ?></p><?php endif ?>
        <div class="actions">
            <?php if ($task['can_cancel']): $post('/ai/tasks','cancel',['id'=>$task['id']],'Hentikan tugas'); endif ?>
            <?php if ($task['can_review'] && $can('report.review')):
                foreach (['verified'=>'Verifikasi','needs_revision'=>'Perlu revisi','incorrect'=>'Laporkan tidak tepat'] as $decision=>$label)
                    $post('/ai/tasks','review',['id'=>$task['id'],'decision'=>$decision],$label);
            endif ?>
            <a class="btn btn-outline-secondary" href="<?= escape($path . '/json') ?>">Ekspor JSON</a>
            <?php if ($can('report.generate') && ($result['review_status'] ?? '') === 'verified'): ?>
                <a class="btn btn-primary" href="<?= escape($path . '/pdf') ?>">Unduh PDF terverifikasi</a>
            <?php endif ?>
        </div>
    </section>
    <?php if ($result && isset($result['summary'])): ?>
        <section class="panel spaced"><h2>Ringkasan</h2><p id="ai-summary"><?= escape($result['summary']) ?></p>
            <p>Keparahan sumber · <?= escape($result['source_severity']) ?> · Tinjauan <?= escape($result['review_status']) ?></p>
            <p>Model · <?= escape($result['model_name'] ?? 'Inferensi tidak dijalankan') ?></p>
            <ul><?php foreach ($result['limitations'] as $row): ?><li><?= escape($row) ?></li><?php endforeach ?></ul>
            <button class="btn btn-outline-secondary" type="button" data-ai-copy="ai-summary">Salin ringkasan</button>
        </section>
        <details class="panel spaced"><summary>Temuan teknis</summary><?php $list($result['technical_findings'],['text'=>'Fakta']); ?></details>
        <section class="panel spaced"><h2>Referensi yang dipakai</h2><?php $list($result['source_references'],['id'=>'Sitasi','title'=>'Judul','reference'=>'Rujukan','published'=>'Tanggal','sha256'=>'Checksum']); ?></section>
        <section class="panel"><h2>Saran untuk peninjauan</h2><?php $list($result['recommendations'],['priority'=>'Prioritas','text'=>'Saran','origin'=>'Dasar']); ?></section>
    <?php elseif ($result || $task['metrics']): ?>
        <section class="panel"><h2>Metrik dan hasil</h2><pre class="ti-value"><?= escape(json_encode(['result'=>$result,'metrics'=>$task['metrics']], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) ?></pre></section>
    <?php endif ?>
<?php elseif ($section === 'knowledge' || $section === 'rag'): ?>
    <?php if ($section === 'rag'): ?>
        <form class="panel filter-grid" method="get"><?php $input('Cari topik atau CVE','q',text_input($_GET,'q')); ?><button class="btn btn-primary">Cari referensi</button></form>
        <?php if ($data['results']): ?>
        <section class="panel spaced"><h2>Hasil pencarian · <?= escape($data['results']['retrieval']['method']) ?></h2>
            <?php $list($data['results']['documents'],['title'=>'Judul','source'=>'Sumber','reference'=>'Rujukan','published'=>'Tanggal']); ?></section>
        <?php endif ?>
    <?php else: ?>
        <?php if ($can('knowledge.manage')): ?>
            <details class="panel spaced"><summary>Ajukan dokumen teknis</summary><form method="post" class="record-form">
                <input type="hidden" name="_csrf" value="<?= $csrf ?>">
                <label>Dokumen JSON yang telah diperiksa untuk data sensitif<textarea class="form-control" name="document" rows="8" required></textarea></label>
                <button class="btn btn-primary" name="action" value="submit">Simpan draf</button>
            </form></details>
        <?php endif ?>
        <details class="panel spaced"><summary>Sumber pengetahuan</summary>
            <?php $list($data['sources'],['title'=>'Sumber','enabled'=>'Aktif (1/0)'],$can('knowledge.manage') ?
                static function($row) use ($post): void { $post('/ai/knowledge','source',['source'=>$row['code'],'enabled'=>$row['enabled'] ? '0' : '1'],$row['enabled'] ? 'Nonaktifkan' : 'Aktifkan'); } : null); ?>
        </details>
        <?php if ($doc = $data['document']): ?>
            <section class="panel spaced"><h2><?= escape($doc['title']) ?></h2><p>SHA-256 · <?= escape($doc['checksum']) ?></p>
                <pre class="ti-value"><?= escape($doc['content']) ?></pre>
                <pre class="ti-value"><?= escape(json_encode($doc['facts'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) ?></pre>
                <?php if ($can('knowledge.approve') && $doc['state'] === 'draft'): ?>
                <form class="record-form" method="post" action="/ai/knowledge">
                    <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($doc['id']) ?>">
                    <label class="choice"><input type="checkbox" name="reviewed" value="1" required> Saya telah memeriksa fakta, rujukan, dan klasifikasi data.</label>
                    <label class="choice"><input type="checkbox" name="embed" value="1"> Buat embedding lokal.</label>
                    <button class="btn btn-primary" name="action" value="approve">Setujui dokumen</button>
                </form>
                <?php endif ?>
            </section>
        <?php endif ?>
    <?php endif ?>
    <section class="panel"><h2>Dokumen dan indeks</h2>
        <?php $list($data['docs'],['title'=>'Judul','id'=>'ID dokumen','version'=>'Versi','source'=>'Sumber','state'=>'Status','index_status'=>'Indeks'],
            static function($row) use ($section,$post,$can): void { ?>
            <a href="/ai/knowledge?id=<?= escape($row['id']) ?>">Tinjau</a>
            <?php if ($can('knowledge.approve') && $row['state'] === 'approved'): ?>
                <?php if ($section === 'rag' && $can('knowledge.manage')) $post('/ai/rag','index',['id'=>$row['id']],'Indeks ulang'); ?>
                <?php if ($section === 'knowledge') $post('/ai/knowledge','archive',['id'=>$row['id']],'Arsipkan'); ?>
            <?php endif ?>
        <?php }); ?>
    </section>
<?php elseif ($section === 'models'): ?>
    <section class="panel spaced"><h2>Model terpasang · <?= escape($data['models']['runtime']) ?></h2>
        <?php $list($data['models']['installed'],['name'=>'Nama','digest'=>'Digest','quantization'=>'Kuantisasi','size'=>'Ukuran (byte)']); ?>
        <details><summary>Setujui model terpasang</summary><form class="record-form" method="post">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <?php $input('Nama persis pada runtime','name'); $select('Peran','role',['inference','embedding']); $input('Referensi lisensi HTTPS','license'); ?>
            <label class="choice"><input type="checkbox" name="reviewed" value="1" required> Model dan lisensi telah ditinjau.</label>
            <button class="btn btn-primary" name="action" value="approve">Simpan persetujuan</button>
        </form></details>
    </section>
    <?php foreach ($data['models']['approved'] as $model): ?>
    <section class="panel spaced"><h2><?= escape($model['name']) ?> · <?= escape($model['role']) ?></h2>
        <p><?= $model['active'] ? 'Aktif' : 'Nonaktif' ?> · <?= $model['available'] ? 'Digest cocok' : 'Model atau digest tidak tersedia' ?></p>
        <div class="actions">
            <?php $post('/ai/models','activation',['id'=>$model['id'],'active'=>$model['active'] ? '0' : '1'],$model['active'] ? 'Nonaktifkan' : 'Aktifkan');
            if ($model['role'] === 'inference') $post('/ai/models','benchmark',['id'=>$model['id']],'Jalankan benchmark'); ?>
        </div>
        <details><summary>Opsi model</summary><form method="post" class="record-form">
            <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= escape($model['id']) ?>">
            <?php foreach (['context'=>'Konteks','temperature'=>'Temperatur','top_p'=>'Top P','max_output'=>'Batas token'] as $key=>$label)
                $input($label,$key,(string)$model['options'][$key]);
            $select('Perangkat','device',array_unique([$model['options']['device'],'auto','cpu'])); ?>
            <button name="action" value="options" class="btn btn-primary">Simpan opsi</button>
        </form></details>
    </section>
    <?php endforeach ?>
<?php elseif ($section === 'evaluation'): ?>
    <section class="panel spaced"><?php $post('/ai/evaluation','run',[],'Jalankan evaluasi retrieval'); ?></section>
    <section class="panel"><?php $list($data['evaluation'],['id'=>'Tugas','state'=>'Status','created_at'=>'Waktu'],static function($row): void { ?>
        <a href="/ai/tasks/<?= escape($row['id']) ?>">Hasil</a><?php }); ?></section>
<?php elseif ($section === 'audit'): ?>
    <section class="panel"><?php $list($data['events'],['occurred_at'=>'Waktu','actor'=>'ID pseudonim','action'=>'Aksi','object_id'=>'Objek','outcome'=>'Hasil']); ?></section>
<?php elseif ($section === 'settings'): ?>
    <section class="panel spaced"><h2>Retensi tugas dan audit</h2><form class="record-form" method="post">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <?php $input('Hari yang dipertahankan (7–3650)','days','180','number'); ?>
        <label class="choice"><input type="checkbox" name="confirm" value="1" required> Hapus riwayat lama sesuai kebijakan institusi.</label>
        <button class="btn btn-primary" name="action" value="retention">Terapkan retensi</button>
    </form></section>
    <?php if ($data['template']): ?><section class="panel"><h2>Template yang berlaku</h2><pre class="ti-value"><?= escape(json_encode($data['template'], JSON_PRETTY_PRINT)) ?></pre></section><?php endif ?>
<?php endif ?>
