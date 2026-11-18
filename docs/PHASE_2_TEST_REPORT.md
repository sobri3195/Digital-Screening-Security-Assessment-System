# Laporan pengujian Fase 2

Lingkungan uji memakai PHP 8.4.24 dan MariaDB 11.8.6 dengan basis data disposable. Migrasi diuji pada instalasi dengan data Fase 1 serta pada skema baru, kemudian dijalankan ulang.

| Pemeriksaan | Hasil |
| --- | --- |
| Fase 1 | 11 pemeriksaan unit dan 124 permintaan HTTP lulus |
| Fase 2 | 37 pemeriksaan unit/integrasi dan 62 pemeriksaan HTTP lulus |
| CISA KEV | Sinkronisasi HTTPS nyata menerima dan menyimpan 1.782 CVE, 0 ditolak |
| NVD dan FIRST EPSS | Parser fixture lulus. Akses langsung diblokir egress cloud (403) |
| URLhaus, ThreatFox, MalwareBazaar | Parser fixture lulus. Pengujian langsung memerlukan kunci dan izin institusional |
| BSSN, Kemenkes | Parser DOM/RSS dan impor advisori dengan fixture lulus. Pengambilan online belum tersedia |

Pemeriksaan mencakup validasi dan defanging, redaksi query, penolakan DTD, deduplikasi feed dan antrean, retry dan rate limit melalui fixture, bukti dan checksum, impor/ekspor offline, RBAC dan scope API, pencocokan aset, alert, serta pembuatan PDF.

## Benchmark sintetis

Pemuatan menggunakan data domain bertanda TEST dan satu observasi per domain, dalam batch SQL 10.000. Pemuatan kumulatif awal selesai sekitar 0,34 detik pada 10.000, 3,09 detik pada 100.000, dan 244,75 detik pada 1.000.000 saat ada benchmark kedua yang berbagi database server. Pencarian fingerprint rata-rata sekitar 0,17, 0,14, dan 0,13 ms pada tiga ukuran itu. Peak memori proses PHP adalah 2 MiB. Pengukuran memori ini tidak mencakup server MariaDB. Optimasi kueri keyset kemudian menghasilkan halaman 25 baris dalam 6,82–34,54 ms pada database berisi 1 juta indikator (tiga cursor). Hasil ini mengukur pencarian indeks dan pagination, dengan data sintetis satu tipe, tanpa klaim latensi dashboard, kebutuhan produksi, atau volume provider nyata.

## Menjalankan ulang

Pada basis data disposable berawalan `sentinel_phase_`, jalankan migrasi dan siapkan admin sesuai panduan instalasi. Mulai server dev dengan ekstensi cURL, Intl, dan GD. Set `DB_NAME`, `SENTINEL_TEST_URL`, `SENTINEL_TEST_USER` dan `SENTINEL_TEST_PASSWORD_FILE` untuk instans yang sama. Jalankan urutan berikut.

```sh
php tests/run.php
python3 tests/smoke.py
php tests/threat.php --integration
python3 tests/threat_smoke.py
php bin/threat.php maintenance
```

Pada skema benchmark khusus yang masih kosong jalankan `DB_NAME=sentinel_phase_benchmark php tests/threat_benchmark.php`. Uji koneksi resmi menggunakan provider CISA yang diaktifkan dan `php bin/threat.php tick` pada skema terpisah.
