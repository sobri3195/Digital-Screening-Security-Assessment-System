# Instalasi

## Prasyarat

PHP 8.3+ dengan PDO MySQL, fileinfo, GD, sodium, mbstring, DOM, dan ekstensi yang diminta Composer. Siapkan MariaDB atau MySQL, Composer 2, Node.js dan npm. Gunakan `npm ci` dan `composer install` di mesin yang mempunyai akses ke registry sebelum membawa checkout beserta `vendor/` dan `public/assets/vendor/` ke intranet.

## Konfigurasi

Buat database `puskesau_sentinel` dengan `utf8mb4`. Buat kredensial khusus untuk aplikasi dan isi `.env` dari contoh. Akun untuk migrasi memerlukan DDL dan DML di database tersebut. Setelah migrasi, gunakan akun aplikasi terpisah dengan grant sesuai [kebijakan keamanan](SECURITY_POLICY.md). Simpan `.env` dan direktori `storage/` dengan akses terbatas untuk operator dan proses PHP.

```bash
composer install --no-interaction
npm ci
npm run assets
php bin/setup.php key
php bin/setup.php migrate
```

Simpan hasil perintah `key` di `APP_KEY` sebelum mengaktifkan TOTP atau membuat backup. Buat administrator di Bash tanpa menyimpan kata sandi ke command history.

```bash
read -rs sentinel_password
printf '%s\n' "$sentinel_password" | php bin/setup.php admin admin-sentinel
unset sentinel_password
```

Di PowerShell, gunakan `Read-Host -AsSecureString`, konversikan dalam proses sementara untuk mengirimnya ke stdin perintah PHP, atau gunakan Git Bash dengan perintah di atas. Hindari password sebagai argumen proses.

## Windows dengan XAMPP atau Laragon

Pilih distribusi PHP 8.3+ dan pastikan `php -v` merujuk ke instalasi yang sama dengan Apache. Aktifkan ekstensi yang diperlukan pada `php.ini`, lalu restart Apache. Tambahkan virtual host lokal dengan document root seperti `C:/sites/puskesau-sentinel/public` dan aktifkan `mod_rewrite`.

```apache
<VirtualHost *:80>
    ServerName sentinel.local
    DocumentRoot "C:/sites/puskesau-sentinel/public"
    <Directory "C:/sites/puskesau-sentinel/public">
        AllowOverride All
        Require local
    </Directory>
</VirtualHost>
```

Petakan `sentinel.local` ke `127.0.0.1` di Windows hosts file. Untuk intranet gunakan virtual host TLS dan aturan akses sesuai jaringan institusi. Pilih `APP_SECURE_COOKIE=0` hanya saat menjalankan HTTP di localhost.

## Linux dengan Nginx dan PHP-FPM

Pasang PHP-FPM dan sertifikat internal. Contoh bagian konfigurasi virtual host TLS.

```nginx
root /srv/sentinel/public;
index index.php;
client_max_body_size 12m;
location / {
    try_files $uri $uri/ /index.php?$query_string;
}
location = /index.php {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root/index.php;
    fastcgi_param HTTP_AUTHORIZATION $http_authorization;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;
}
location ~ \.php$ { return 404; }
location = /vercel.json { return 404; }
location ~ /\. { deny all; }
```

Sesuaikan jalur socket dengan versi PHP, set `APP_SECURE_COOKIE=1`, `upload_max_filesize=10M` dan `post_max_size=12M`. Tambahkan HSTS bila sertifikat telah dipercaya klien. Pastikan `display_errors=Off` dan batasi akses log. Apache Linux dapat menggunakan pola virtual host di atas dengan jalur Linux dan HTTPS.

Untuk pengembangan, jalankan `php -d upload_max_filesize=10M -d post_max_size=12M -S 127.0.0.1:8080 -t public bin/router.php`. Verifikasi halaman login dan `/api/v1/health`.
