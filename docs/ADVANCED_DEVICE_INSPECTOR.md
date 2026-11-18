# Pengoperasian Device Inspector

1. Daftarkan aset dengan kode inventaris dan unit.
2. Pada Ruang kerja, pilih aset, isi kode petugas dan rujukan izin, lalu konfirmasikan ruang lingkup. Centang konfirmasi host jika memeriksa komputer Windows yang menjalankan Inspector.
3. Pada mode Quick atau Comprehensive, tinjau modul yang diusulkan. Mode Custom membolehkan pemilihan langsung. Checklist seluler menggunakan tab khusus. Untuk analisis file, pilih file teknis dengan picker atau drag-and-drop. Untuk kerentanan, masukkan vendor, produk dan versi yang telah diperiksa atau jalankan inventaris Windows terlebih dahulu.
4. Mulai pemeriksaan dan tinjau progres serta catatan. Batalkan jika ruang lingkup berubah. Sesi dan bukti dapat dibuka dari Riwayat. Catat tindak lanjut sebelum mengekspor dan menutup sesi.

Dashboard menampilkan hitungan lokal, penggunaan CPU/RAM, pembaruan katalog, ruang disk dan status pemeriksaan API. Tombol API hanya menguji origin HTTPS yang dimasukkan operator. Daftar aset, bukti, dan file tidak dikirim.

CLI menyediakan `asset-add`, `inspect`, `show`, `summary`, `lookup`, `intel-import`, `report`, `verify-audit`, `backup`, dan `restore`. Gunakan `--db PATH` sebelum subcommand untuk memilih database. File JSON pemeriksaan memakai objek `authorization` dan daftar opsional `files`, `checks`, `indicators`, `products`, serta `engines`. Validasi input mengikuti skema `desktop/src/sentinel_inspector/models.py`; jalur file harus absolut dan lokal.
