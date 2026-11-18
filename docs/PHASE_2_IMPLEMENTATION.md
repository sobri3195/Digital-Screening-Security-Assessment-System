# PUSKESAU SENTINEL Fase 2

Threat Intelligence menggunakan routing, PDO, RBAC, sesi, CSRF, dan audit Fase 1. Jalankan `composer install`, `npm ci`, `npm run assets`, dan `php bin/setup.php migrate`. PHP memerlukan cURL dan Intl. Data baru berasal dari basis data dan worker, dengan provider otomatis nonaktif saat instalasi. Migrasi `004_threat_catalog.sql` menambah 16 tabel dan inisialisasi satu kali menetapkan izin serta provider.

- Controller `Threat` dan `ThreatApi` menangani antarmuka web dan API.
- `app/Services/Threat/` memuat normalisasi, pencarian lokal, prioritas, feed, antrean, transfer, dan laporan.
- `app/Views/threat/` memuat dashboard, kategori pemeriksaan, katalog, advisori, konfigurasi, dan monitor.
- `bin/threat.php` menjalankan antrean dan pemeliharaan. `tests/` mencakup analisis, workflow dan benchmark sintetis.

Fase ini mendukung korelasi lokal antara URL dan hostname, IOC dan sumbernya, hash dan keluarga malware, CVE dengan KEV/EPSS, serta kandidat kecocokan aset. Korelasi ditampilkan sebagai bukti beratribusi pada hasil pemeriksaan. Grafik hubungan, pengaitan insiden Fase 1, auto-matching inventaris, dan full disaster recovery katalog TI dapat dikembangkan pada Fase 3. Dukungan aset meliputi nama produk/vendor dan perbandingan versi sederhana, dengan hasil yang memerlukan triase manusia. BSSN dan Kemenkes tersedia melalui input atau impor salinan publikasi yang diotorisasi. VirusTotal dan AlienVault OTX belum terintegrasi.

- [Panduan operasi](THREAT_INTELLIGENCE_GUIDE.md), [feed](THREAT_FEED_CONFIGURATION.md), [rahasia](API_KEYS_CONFIGURATION.md), dan [scheduler](SYNC_SCHEDULER_GUIDE.md).
- [Skema](IOC_DATABASE_SCHEMA.md), [metodologi skor](RISK_SCORING_METHODOLOGY.md), [offline](OFFLINE_MODE_GUIDE.md), [parser advisori](WEB_SCRAPING_GUIDE.md), dan [OpenAPI](threat-openapi.yaml).
- [Penilaian keamanan](SECURITY_ASSESSMENT.md) dan [hasil pengujian](PHASE_2_TEST_REPORT.md).
