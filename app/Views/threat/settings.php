<?php require __DIR__ . '/common.php'; ?>
<section class="panel">
    <form method="post" class="record-form">
        <input type="hidden" name="_csrf" value="<?= $csrf ?>">
        <?php $input('Retensi riwayat pemeriksaan dan job (7–365 hari)','history_days','number',$data['settings']['history_days'],true);
        $input('Ambang prioritas alert (15–100)','alert_priority','number',$data['settings']['alert_priority'],true); ?>
        <button class="btn btn-primary" name="action" value="save">Simpan pengaturan</button>
    </form>
</section>
