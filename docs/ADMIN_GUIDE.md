# Panduan administrator

Role awal terdiri dari Super Administrator, Administrator, Petugas Pemeriksaan, Supervisor, Pimpinan, serta Auditor. Hak akses menggunakan kumpulan izin yang disimpan di database. Kelola pengguna dan hak akses dari menu Sistem. Reset kata sandi dan penonaktifan akun mencabut sesi yang ada. Gunakan prosedur internal terotorisasi untuk pemulihan akses bila perangkat TOTP hilang.

Atur kop melalui kunci `institution_name` dan unggah logo institusi yang telah diotorisasi dari Pengaturan Aplikasi. Klien desktop dibuat di Integrasi API dengan scope baca minimum. Rahasia ditampilkan saat dibuat atau saat rotasi. Simpan di penyimpanan rahasia yang disetujui.

## Backup dan pemulihan

- Gunakan Backup dan Restore atau jalankan `php bin/maintenance.php backup` melalui cron atau Windows Task Scheduler.
- Backup aplikasi mencakup tabel operasional yang tercantum di `app/Services/Backup.php`. Untuk pemulihan bencana penuh, buat juga backup database yang dikelola operator, termasuk autentikasi, audit, dan metadata file, serta backup privat `storage/`. Simpan `APP_KEY` terpisah dengan prosedur escrow institusi.
- Pulihkan ke database staging lebih dahulu. Pada instance yang dituju, hentikan penulisan selama pemulihan. Ambil backup terbaru, buka cadangan yang tepat, periksa ketergantungan akun dan data, lalu konfirmasi dengan mengetik `PULIHKAN`. Database menggunakan transaksi dan checksum serta autentikasi ciphertext diperiksa.
- Jalankan `php bin/maintenance.php retention` secara berkala. Uji pemulihan penuh menggunakan perangkat backup operator dan lakukan pemeriksaan akses setelah pemulihan.

## Demo

Jalankan `php database/seeders/demo.php seed` dengan kata sandi demo melalui stdin. Pengguna sintetis bernama `demo-1` hingga `demo-6`. Jalankan `php database/seeders/demo.php purge DEMO` sebelum penggunaan produksi. Penghapusan dibatalkan jika data lain masih merujuk entri demo yang dilindungi foreign key. Gunakan database demo terpisah dari produksi.
