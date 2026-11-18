# Scheduler dan worker

Dari root repository jalankan `php bin/threat.php tick` untuk antrean jatuh tempo dan maksimal sepuluh job siap. `schedule` hanya menjadwalkan dan `work 10` hanya menjalankan job. Untuk memeriksa koneksi, antrekan **Uji dan pratinjau** di UI lalu jalankan worker.

Untuk Cron Linux, tambahkan perintah berikut dengan jalur instalasi yang benar.

```cron
* * * * * cd /srv/sentinel && /usr/bin/php bin/threat.php tick
15 2 * * * cd /srv/sentinel && /usr/bin/php bin/threat.php maintenance
```

Di Windows Task Scheduler gunakan executable PHP dengan argumen `bin/threat.php tick`, isi **Start in** dengan root repository, dan gunakan trigger pengulangan setiap menit. Buat task harian untuk `maintenance` dan jalankan dengan akun yang membaca konfigurasi aplikasi. Hentikan worker saat pemulihan basis data.

Worker mengambil lock database, memakai lease lima menit dan menyimpan checkpoint per halaman dalam transaksi. Kegagalan koneksi, 429, dan 5xx menggunakan backoff eksponensial dengan minimal 60 detik atau `Retry-After` jika lebih lama. Setelah percobaan kelima, job gagal dan menghasilkan alert.
