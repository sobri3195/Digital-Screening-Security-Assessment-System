# PUSKESAU SENTINEL Fase 2

Threat Intelligence menggunakan routing, PDO, RBAC, sesi, CSRF, dan audit Fase 1. Jalankan `composer install`, `npm ci`, `npm run assets`, dan `php bin/setup.php migrate`. PHP memerlukan cURL dan Intl. Data baru berasal dari basis data dan worker, dengan provider otomatis nonaktif saat instalasi. Migrasi `004_threat_catalog.sql` menambah 16 tabel dan inisialisasi satu kali menetapkan izin serta provider.

- Controller `Threat` dan `ThreatApi` menangani antarmuka web dan API.
- `app/Services/Threat/` memuat normalisasi, pencarian lokal, prioritas, feed, antrean, transfer, dan laporan.
- `app/Views/threat/` memuat dashboard, kategori pemeriksaan, katalog, advisori, konfigurasi, dan monitor.
- `bin/threat.php` menjalankan antrean dan pemeliharaan. `tests/` mencakup analisis, workflow dan benchmark sintetis.

Fase ini mendukung korelasi lokal antara URL dan hostname, IOC dan sumbernya, hash dan keluarga malware, CVE dengan KEV/EPSS, serta kandidat kecocokan aset. Korelasi ditampilkan sebagai bukti beratribusi pada hasil pemeriksaan. Worker menyediakan backfill NVD dan pencocokan inventaris per batch. Petugas dapat menautkan CVE ke insiden, dan ringkasan Desktop yang diterima API tampil di rincian aset. Kecocokan nama produk/vendor dan versi tetap memerlukan triase. BSSN dan Kemenkes dapat diimpor dari salinan resmi melalui web atau CLI. [Konfigurasi feed](THREAT_FEED_CONFIGURATION.md) · [Pemulihan bencana](DISASTER_RECOVERY.md)

- [Panduan operasi](THREAT_INTELLIGENCE_GUIDE.md), [feed](THREAT_FEED_CONFIGURATION.md), [rahasia](API_KEYS_CONFIGURATION.md), dan [scheduler](SYNC_SCHEDULER_GUIDE.md).
- [Skema](IOC_DATABASE_SCHEMA.md), [metodologi skor](RISK_SCORING_METHODOLOGY.md), [offline](OFFLINE_MODE_GUIDE.md), [parser advisori](WEB_SCRAPING_GUIDE.md), dan [OpenAPI](threat-openapi.yaml).
- [Penilaian keamanan](SECURITY_ASSESSMENT.md) dan [hasil pengujian](PHASE_2_TEST_REPORT.md).
