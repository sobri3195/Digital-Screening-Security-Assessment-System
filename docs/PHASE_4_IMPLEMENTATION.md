# PUSKESAU SENTINEL Fase 4

Device Inspector 1.1.0 adalah modul desktop Python 64-bit yang memakai database SQLite milik akun OS. Branch dasar memuat Fase 1 dan Fase 2. Source desktop Fase 3 dan skemanya tidak ditemukan, sehingga modul desktop baru ditempatkan di `desktop/`. Integrasi merupakan impor katalog Fase 2 dan pemeriksaan manual endpoint kesehatan API. Web Fase 1 dan 2 tetap memakai database yang sama. Tidak ada migrasi MySQL baru dalam perubahan ini.

| Area | Implementasi |
| --- | --- |
| Inspeksi | Otorisasi per aset, tugas yang dibatasi kategori, pemilihan file eksplisit, pembatalan, bukti, dan linimasa |
| Perangkat | Monitor USB berbasis Windows CIM, pembacaan konfigurasi dan inventaris Windows, checklist Android/iOS manual |
| Analisis | Signature, hash, metadata ZIP, APK statis, YARA opsional, adaptor Defender dan ClamAV, pencarian dan kandidat kerentanan dari katalog lokal |
| Pelaporan | Triase dan mitigasi, posture dengan cakupan minimum dan aturan berversi, pratinjau, print, PDF, JSON dan CSV |
| Operasi | SQLite berversi, backup terenkripsi, verifikasi audit, UI PySide6, skrip build Windows x64 |

## Instalasi dan penggunaan

Dari root checkout, instal `python -m pip install -e "./desktop[gui,yara,test]"` di virtual environment Python 3.12 x64, lalu jalankan `python -m sentinel_inspector`. Lihat panduan penggunaan untuk opsi CLI dan file database. Koneksi web hanya diuji saat operator menekan tombol uji; data pemeriksaan tetap di workstation.

## Batasan dan Fase 5

Validasi Windows 10/11, hot-plug USB fisik, Defender dan ClamAV dengan signature aktif, APK yang ditandatangani dalam skema v2/v3, dan penerimaan installer masih diperlukan. Password policy, Windows auditing, status patch compliance, dan dukungan produk memerlukan sumber kebijakan yang belum terhubung. Integrasi Fase 3, SSO/RBAC lintas perangkat, sinkronisasi hasil pemeriksaan, dan verifikasi integritas terpusat adalah pekerjaan berikutnya. Gunakan data sintetis dan aset lab untuk penerimaan sebelum deployment.

- [Panduan penggunaan](ADVANCED_DEVICE_INSPECTOR.md), [database](DATABASE_MIGRATION.md), dan [build Windows](BUILD_EXE_GUIDE.md).
- [USB](USB_DEVICE_MONITOR_GUIDE.md), [Windows](WINDOWS_SECURITY_INSPECTOR.md), [Android](ANDROID_SECURITY_CHECKLIST.md), dan [iOS](IOS_SECURITY_CHECKLIST.md).
- [YARA](YARA_SCANNER_GUIDE.md), [APK](APK_SECURITY_ANALYSIS.md), [malware](MALWARE_SCANNER_GUIDE.md), dan [kerentanan](VULNERABILITY_ASSESSMENT.md).
- [Bukti](TECHNICAL_EVIDENCE_GUIDE.md), [posture](SECURITY_SCORING_METHODOLOGY.md), [mitigasi](MITIGATION_GUIDE.md), dan [pengujian](PHASE_4_TEST_REPORT.md).
