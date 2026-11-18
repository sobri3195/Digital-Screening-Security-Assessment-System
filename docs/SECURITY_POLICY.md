# Kebijakan keamanan

Gunakan data teknis institusi menurut ruang lingkup dan otorisasi yang terdokumentasi. Hindari informasi pribadi peserta dan rahasia di deskripsi, nama file, atau jalur URL. Pemeriksaan tidak membuat koneksi ke URL masukan. Berkas masuk tidak dieksekusi atau disajikan dari web root.

Jalankan di jaringan internal dengan HTTPS. Batasi hak OS dan database proses web. Gunakan akun migrasi terpisah, dan untuk database produksi batasi hak `audit_logs` menjadi SELECT dan INSERT bagi akun aplikasi. Tangani retensi log menggunakan akun pemeliharaan terpisah sesuai kebijakan. Batasi akses ke file konfigurasi, direktori penyimpanan, arsip Cadangan, dan log web. Pertahankan `APP_KEY` selama data terenkripsi lama masih diperlukan.

Otorisasi memakai grup izin backend dan default ditolak. Akun untuk peran yang sama dapat melihat data modul yang sama. Tambahkan cakupan unit atau penugasan sebelum mengoperasikan aplikasi sebagai sistem multi-tenant. Audit tidak menyimpan kata sandi, token, atau isi catatan pemeriksaan.

Uji staging, tinjau aturan akses dan kebijakan data, dan lakukan penilaian keamanan independen sebelum akses produksi. Laporkan temuan keamanan melalui kanal internal institusi.
