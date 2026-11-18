<?php use Sentinel\Core\Auth; $csrf = escape(Auth::csrf()); ?>
<div class="page-heading"><h1>Profil Saya</h1></div>
<div class="chart-grid">
    <section class="panel"><h2>Informasi akun</h2><p><?= escape($user['username']) ?></p>
        <form method="post" class="record-form"><input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <label>Nama <input class="form-control" name="title" value="<?= escape($user['title']) ?>" maxlength="160" required></label>
            <label>Kata sandi saat ini <input type="password" class="form-control" name="current" autocomplete="current-password" required></label>
            <button class="btn btn-primary" name="action" value="name">Simpan profil</button>
        </form>
    </section>
    <section class="panel"><h2>Ubah kata sandi</h2>
        <form method="post" class="record-form"><input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <label>Kata sandi saat ini <input type="password" class="form-control" name="current" autocomplete="current-password" required></label>
            <label>Kata sandi baru <input type="password" class="form-control" name="new" autocomplete="new-password" minlength="12" required></label>
            <button class="btn btn-primary" name="action" value="password">Ubah kata sandi</button>
        </form>
    </section>
    <section class="panel"><h2>Autentikasi dua faktor</h2>
        <?php if ($user['totp_secret'] !== null): ?><p>TOTP aktif.</p><?php else: ?>
        <form method="post" class="record-form"><input type="hidden" name="_csrf" value="<?= $csrf ?>">
            <?php if ($data['setup']): ?>
                <p>Tambahkan kunci ini ke aplikasi autentikator berbasis waktu. Masukkan kode enam digit untuk mengaktifkan TOTP.</p>
                <code><?= escape($data['setup']) ?></code>
                <label>Kode TOTP <input class="form-control" name="totp" required pattern="[0-9]{6}" inputmode="numeric" autocomplete="one-time-code"></label>
            <?php endif ?>
            <label>Kata sandi saat ini <input class="form-control" type="password" name="current" required autocomplete="current-password"></label>
            <button class="btn btn-primary" name="action" value="<?= $data['setup'] ? 'totp-confirm' : 'totp-start' ?>"><?= $data['setup'] ? 'Aktifkan TOTP' : 'Siapkan TOTP' ?></button>
        </form><?php endif ?>
    </section>
    <section class="panel"><h2>Riwayat login</h2><ul class="activity-list">
        <?php foreach ($data['history'] as $entry): ?><li><span><?= escape($entry['result']) ?></span><time><?= escape($entry['created_at']) ?></time></li><?php endforeach ?>
    </ul></section>
</div>
