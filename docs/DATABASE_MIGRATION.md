# Migrasi SQLite

`001_initial.sql` membuat aset, otorisasi, sesi, tugas, bukti, temuan, USB, katalog, laporan, dan rantai audit. `002_scoring_settings.sql` menambah versi posture per sesi dan konfigurasi aktif. Fitur yang terkait memakai tabel bersama untuk menghindari pengulangan skema. Aplikasi menjalankan migrasi dalam transaksi saat membuka database. Database default Windows berada di `%LOCALAPPDATA%\PuskesauSentinel\inspector.sqlite3`. Basis data web tidak diubah.

Migrasi 003 membekukan data laporan dari sesi tertutup. Setelah koreksi, pilih revisi yang diinginkan pada GUI atau gunakan `report SESSION JENIS OUTPUT --revision NOMOR`. Sesi lama memakai metadata yang tersedia saat upgrade.

Skrip rollback tersedia dan telah diuji pada database disposable. Rollback 003 menghapus snapshot revisi. Rollback 002 menghapus rujukan versi per sesi. Rollback 001 menghapus tabel Inspector. Ambil backup terenkripsi sebelum migrasi atau rollback dan pulihkan ke lokasi baru. Gunakan `--db` untuk membuka salinan pulih. Simpan folder di bawah ACL akun operator dan gunakan kebijakan institusi untuk retensi laporan, sesi, dan backup.
