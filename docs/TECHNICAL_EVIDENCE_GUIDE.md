# Bukti dan integritas audit

Riwayat menampilkan metadata bukti, sumber, timestamp UTC, modul dan SHA-256. Inspector menghitung kembali checksum saat bukti dibuka. File asli, isi kecocokan YARA, serial PnP, dan jalur file tidak disimpan. Pengubahan status temuan disertai kode petugas dan catatan teknis. Jangan menambahkan informasi pribadi ke catatan atau nama file.

Verifikasi audit melalui Sistem atau `sentinel-inspector verify-audit`. Rantai SHA-256 membantu menemukan perubahan tak sengaja. Operator dengan akses penuh ke penyimpanan dapat menulis ulang riwayat dan checksum, sehingga gunakan akses OS, backup terenkripsi, dan ekspor yang ditandatangani untuk verifikasi independen bila diperlukan.
