# Skema intelijen

| Area | Tabel |
| --- | --- |
| Provider dan sinkronisasi | ti_providers, ti_sync_jobs, ti_sync_logs, ti_settings |
| IOC dan bukti | ti_indicators, ti_indicator_sources, ti_scan_results, ti_scan_matches |
| CVE dan aset | ti_vulnerabilities, ti_asset_vulnerabilities |
| Advisori | ti_advisories, ti_advisory_bookmarks |
| Operasional | ti_reference_domains, ti_alerts, ti_transfers, ti_reports |

Pencarian persis memakai indeks unik tipe dan SHA-256 nilai kanonis. Observasi dideduplikasi menurut indikator dan provider. Metadata, confidence, waktu observasi, waktu pengambilan, parser, dan SHA-256 bukti disimpan pada relasi sumber. Kolom KEV, NVD, dan EPSS terpisah pada baris CVE sehingga pembaruan satu sumber mempertahankan data lainnya. Indeks cursor melayani pagination. Bukti pemindaian dan laporan disimpan sebagai snapshot. Skema DDL terdapat di [migrasi](../database/migrations/004_threat_catalog.sql).
