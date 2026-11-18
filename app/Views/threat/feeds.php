<?php
use Sentinel\Services\Threat\Feeds;
require __DIR__ . '/common.php';
?>
<p>Worker PHP CLI menjalankan antrean di luar permintaan browser. Kunci API dikonfigurasi pada environment server.</p>
<div class="chart-grid">
<?php foreach ($data['providers'] as $provider):
    $automatic = in_array($provider['code'], Feeds::AUTOMATED, true);
    $configured = Feeds::configured($provider['code']);
    $fresh = $provider['last_success_at'] && strtotime($provider['last_success_at']) >= time() - (int) $provider['interval_minutes'] * 120;
    $state = !$automatic ? 'Sumber manual/offline' : (!$configured ? 'Memerlukan konfigurasi' :
        (!$provider['enabled'] ? 'Nonaktif' : ($provider['last_state'] === 'failed' ? 'Sinkronisasi gagal' : ($fresh ? 'Aktif' : ($provider['last_success_at'] ? 'Data kedaluwarsa' : 'Belum sinkron'))))); ?>
    <section class="panel"><h2><?= escape($provider['title']) ?></h2>
        <p class="status"><?= escape($state) ?></p>
        <?php $details($provider,['last_success_at'=>'Sinkronisasi berhasil terakhir','next_run'=>'Kelayakan jadwal berikutnya','last_state'=>'Job terbaru']); ?>
        <?php if ($automatic): ?>
            <form method="post" class="record-form">
                <input type="hidden" name="_csrf" value="<?= $csrf ?>"><input type="hidden" name="provider" value="<?= escape($provider['code']) ?>">
                <?php $select('Aktif (1/0)','active',['0','1'],$provider['enabled']); $input('Interval (menit)','interval','number',$provider['interval_minutes'],true); ?>
                <div class="actions"><button class="btn btn-primary" name="action" value="save">Simpan</button>
                    <?php if ($configured && $can('sync.execute')): ?><button class="btn btn-outline-secondary" name="action" value="preview">Uji dan pratinjau</button>
                        <?php if ($provider['enabled']): ?><button class="btn btn-outline-secondary" name="action" value="sync">Jadwalkan sinkronisasi</button><?php endif ?>
                    <?php endif ?>
                </div>
            </form>
        <?php endif ?>
    </section>
<?php endforeach ?>
</div>
