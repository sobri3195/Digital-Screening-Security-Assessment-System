# Hasil pengujian Fase 4

Pengujian dilakukan dengan Python 3.12.14 pada Linux dan SQLite disposable. **21 tes pytest lulus dan satu tes native Windows dilewati**, termasuk satu alur Qt offscreen yang membuka aplikasi, memilih file, menunggu QThreadPool selesai, melihat bukti dan mengubah tema. Tes memakai aset dan file sintetis. YARA dikompilasi dan dijalankan pada pola teks inert. APK XML dan biner, rentang versi, deduplikasi data, checksum, validasi path, archive limit, backup, restore, pembatalan, migrasi/rollback, bukti dan laporan ikut diuji.

USB connect/disconnect dan Windows configuration diuji dengan respons CIM/PowerShell sintetis. Engine tidak tersedia dan Defender dengan kebijakan cloud aktif ditangani dalam pengujian. Uji langsung konfigurasi, inventaris HKLM, dan enumerasi USB juga lulus di runner Windows Server 2025. USB fisik, Windows 10/11 target, ClamAV dengan signature aktual, dan Defender lokal tetap perlu validasi laboratorium.

Regresi web Fase 1 lulus 124 pemeriksaan HTTP. Fase 2 lulus 37 pemeriksaan unit/integrasi dan 62 pemeriksaan HTTP. Ekspor PHP lintas platform menghasilkan satu halaman berisi 200 CVE dari katalog CISA nyata dan diimpor ke SQLite. Source dan skema Fase 3 tidak tersedia untuk regresi. CI Windows x64 untuk commit `2e88b79` berhasil membuat EXE portable dan installer, menjalankan smoke test EXE portable, memeriksa checksum kedua artefak, dan mengunggah paket. Pengujian pemasangan dan pencopotan installer masih diperlukan. [Build dan artefak](https://github.com/sobri3195/Digital-Screening-Security-Assessment-System/actions/runs/44392997899)

Jalankan ulang dengan `python -m pytest -q desktop/tests` setelah memasang ekstra `gui,yara,test`. Gunakan `QT_QPA_PLATFORM=offscreen` pada Linux tanpa display.
