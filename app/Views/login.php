<?php
use Sentinel\Core\Auth;
use Sentinel\Services\Branding;
?>
<section class="login-shell">
    <div class="login-identity">
        <span class="insignia"><i class="bi bi-shield-lock" aria-hidden="true"></i></span>
        <p class="identity-line">PUSAT KESEHATAN TNI ANGKATAN UDARA</p>
        <h1><strong><?= escape(Branding::NAME) ?></strong></h1>
        <p><?= escape(Branding::EXPANSION) ?></p>
        <button type="button" class="icon-button theme-toggle" title="Ubah tema" aria-label="Ubah tema"><i class="bi bi-circle-half"></i></button>
    </div>
    <form method="post" class="panel login-form">
        <h2>Masuk ke <?= escape(Branding::NAME) ?></h2>
        <?php if (isset($data['message'])): ?><p class="error-message" role="alert"><?= escape($data['message']) ?></p><?php endif ?>
        <input type="hidden" name="_csrf" value="<?= escape(Auth::csrf()) ?>">
        <label>Nama pengguna <input class="form-control" name="username" required autocomplete="username" maxlength="100" autofocus></label>
        <label>Kata sandi <input class="form-control" name="password" type="password" required autocomplete="current-password"></label>
        <label>Kode TOTP <input class="form-control" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" placeholder="Isi jika autentikasi dua faktor aktif"></label>
        <button class="btn btn-primary">Masuk <i class="bi bi-arrow-right" aria-hidden="true"></i></button>
    </form>
</section>
