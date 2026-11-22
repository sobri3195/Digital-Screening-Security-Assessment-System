# MARGONO

**Monitoring, Asset Risk, Governance, Observation, Notifications, and Operations**

MARGONO adalah sistem penilaian keamanan digital untuk administrasi pemeriksaan teknis aset institusi, edukasi, dokumentasi insiden, dan pelaporan internal. Aplikasi menggunakan PHP Native 8.3+, MariaDB atau MySQL, dan aset frontend lokal. Zona waktu aplikasi adalah Asia/Jakarta.

## Mulai

1. Siapkan basis data dan akun MariaDB/MySQL, lalu salin `.env.example` menjadi `.env` dan isi pengaturannya.
2. Jalankan `composer install`, `npm ci`, dan `npm run assets`.
3. Buat kunci aplikasi dengan `php bin/setup.php key` dan simpan hasilnya sebagai `APP_KEY` dalam `.env`.
4. Jalankan `php bin/setup.php migrate` dan buat administrator pertama sesuai [panduan instalasi](docs/INSTALLATION.md).
5. Untuk pengembangan lokal, jalankan `php -S 127.0.0.1:8080 -t public bin/router.php` dari root repository. Untuk intranet gunakan Apache/Nginx dengan HTTPS dan document root `public/`.

Pemeriksaan URL menggunakan heuristik statis. File pemeriksaan disimpan di luar document root. Akun demo dan data sintetis hanya dibuat melalui perintah terpisah.

## Pratinjau publik di Vercel

Gunakan root repository atau `public` sebagai **Root Directory** di proyek Vercel. Keduanya memublikasikan halaman dan aset dari `public/.vercel-preview/` sebagai situs statis. Untuk domain produksi, gunakan deployment **Production** dari branch `main` yang memuat konfigurasi tersebut.

Pratinjau memuat ringkasan produk dan modul. Untuk menjalankan pemeriksaan, pengelolaan akun, dan pelaporan, ikuti [panduan instalasi intranet](docs/INSTALLATION.md).

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

## Device Inspector

Modul desktop Fase 4 tersedia di `desktop/`. Lihat [implementasi dan instalasi Device Inspector](docs/PHASE_4_IMPLEMENTATION.md) untuk pemeriksaan lokal, katalog offline, cakupan Windows, dan langkah membangun paket x64.

## MARGONO AI Engine

Gateway FastAPI Fase 6 menyediakan analisis teknis lokal, pencarian berbasis bukti, serta tinjauan manusia untuk web dan Device Inspector. Integrasi bersifat opsional. [Panduan implementasi Fase 6](docs/PHASE_6_IMPLEMENTATION.md)
