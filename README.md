# PUSKESAU SENTINEL

Digital Security Assessment System untuk administrasi pemeriksaan teknis aset institusi, edukasi, dokumentasi insiden, dan pelaporan internal. Aplikasi menggunakan PHP Native 8.3+, MariaDB atau MySQL, dan aset frontend lokal. Zona waktu aplikasi adalah Asia/Jakarta.

## Mulai

1. Siapkan basis data dan akun MariaDB/MySQL, lalu salin `.env.example` menjadi `.env` dan isi pengaturannya.
2. Jalankan `composer install`, `npm ci`, dan `npm run assets`.
3. Buat kunci aplikasi dengan `php bin/setup.php key` dan simpan hasilnya sebagai `APP_KEY` dalam `.env`.
4. Jalankan `php bin/setup.php migrate` dan buat administrator pertama sesuai [panduan instalasi](docs/INSTALLATION.md).
5. Untuk pengembangan lokal, jalankan `php -S 127.0.0.1:8080 -t public bin/router.php` dari root repository. Untuk intranet gunakan Apache/Nginx dengan HTTPS dan document root `public/`.

Pemeriksaan URL menggunakan heuristik statis. File pemeriksaan disimpan di luar document root. Akun demo dan data sintetis hanya dibuat melalui perintah terpisah.

## Verifikasi

Jalankan `php tests/run.php` untuk unit checks dan ikuti [laporan pengujian](docs/TEST_REPORT.md) untuk smoke test HTTP dengan database disposable.

## Dokumentasi

- [Instalasi](docs/INSTALLATION.md)
- [Panduan penggunaan](docs/USER_GUIDE.md)
- [Panduan administrator](docs/ADMIN_GUIDE.md)
- [API dan OpenAPI](docs/API_DOCUMENTATION.md)
- [Skema database](docs/DATABASE_SCHEMA.md)
- [Kebijakan keamanan](docs/SECURITY_POLICY.md)
- [Retensi data](docs/DATA_RETENTION.md)
- [Laporan pengujian](docs/TEST_REPORT.md)
- [Riwayat perubahan](docs/CHANGELOG.md)
- [Roadmap](docs/ROADMAP.md)

## Threat Intelligence

Jalankan migrasi setelah memperbarui checkout. Menu Threat Intelligence menyediakan katalog lokal, pencarian indikator, antrean feed, dan laporan. Lihat [implementasi Fase 2](docs/PHASE_2_IMPLEMENTATION.md) untuk persyaratan provider, worker, pengujian, dan batasan.
