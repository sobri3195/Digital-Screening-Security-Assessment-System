# Hasil pengujian Fase 4

Pengujian dilakukan dengan Python 3.12.14 pada Linux dan SQLite disposable. **20 tes pytest lulus**, termasuk satu alur Qt offscreen yang membuka aplikasi, memilih file, menunggu QThreadPool selesai, melihat bukti dan mengubah tema. Tes memakai aset dan file sintetis. YARA dikompilasi dan dijalankan pada pola teks inert. APK XML dan biner, rentang versi, deduplikasi data, checksum, validasi path, archive limit, backup, restore, pembatalan, migrasi/rollback, bukti dan laporan ikut diuji.

USB connect/disconnect dan Windows configuration diuji dengan respons CIM/PowerShell sintetis. Engine tidak tersedia dan Defender dengan kebijakan cloud aktif ditangani dalam pengujian. USB fisik, PowerShell pada Windows target, ClamAV dengan signature aktual, dan Defender lokal tetap perlu validasi laboratorium.

Unit PHP Fase 1 dan Fase 2 lulus masing-masing 11 dan 28 pemeriksaan. Ekspor PHP lintas platform menghasilkan satu halaman berisi 200 CVE dari katalog CISA nyata dan diimpor ke SQLite. Source dan skema Fase 3 tidak tersedia untuk regresi. Artefak Windows belum diverifikasi dalam sesi Linux ini.

Jalankan ulang dengan `python -m pytest -q desktop/tests` setelah memasang ekstra `gui,yara,test`. Gunakan `QT_QPA_PLATFORM=offscreen` pada Linux tanpa display.
