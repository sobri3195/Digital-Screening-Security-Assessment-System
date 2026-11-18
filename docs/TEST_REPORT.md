# Laporan pengujian

Pengujian lokal menggunakan PHP 8.4, MariaDB 11.8, Dompdf 3.1, dan Chromium. Database pengujian terpisah menggunakan data sintetis.

| Pemeriksaan | Hasil |
| --- | --- |
| Migrasi dan migrasi ulang | Lulus pada MariaDB |
| Unit checks `php tests/run.php` | 11 lulus |
| Smoke test `python3 tests/smoke.py` | 124 permintaan HTTP dan verifikasi isi lulus |
| Demo | 8 tabel sesuai jumlah yang diminta, kemudian data demo dihapus |
| Chromium desktop dan mobile | Login, grafik, pencarian/rincian aset, sortir tabel, pembatalan dialog hapus, tema, dan navigasi lulus |

Smoke test meliputi sesi login/logout, TOTP termasuk replay, penolakan CSRF, pembatasan login, role Auditor, validasi, dashboard database, operasi data dan CSV, URL, upload dan duplikat, status temuan, timeline, logo dan PDF, scope API, audit, serta backup terenkripsi dan restore operasional.

Npm audit melaporkan nol advisori. Audit Composer khusus berkas lock terhalang respons HTTP 403 dari layanan advisori Packagist. Performa produksi, review keamanan independen, pengujian lintas platform, antivirus, dan pemulihan bencana penuh belum diuji.

## Menjalankan ulang

1. Siapkan database disposable kosong, pasang dependensi, jalankan migrasi, dan buat akun administrator khusus uji.
2. Jalankan development server dengan batas upload sesuai panduan instalasi.
3. Jalankan unit checks dan smoke test.

```bash
php tests/run.php
SENTINEL_TEST_USER=sentinel-test \
SENTINEL_TEST_PASSWORD_FILE=/path/to/private/password-file \
python3 tests/smoke.py
```

`SENTINEL_TEST_URL` dapat mengganti alamat default `http://127.0.0.1:8080`. Smoke test menulis data dan menguji restore. Gunakan database khusus tes.
