# Pengoperasian Device Inspector

1. Daftarkan aset dengan kode inventaris dan unit.
2. Pada Ruang kerja, pilih aset, isi kode petugas dan rujukan izin, lalu konfirmasikan ruang lingkup. Centang konfirmasi host jika memeriksa komputer Windows yang menjalankan Inspector.
3. Pada mode Quick atau Comprehensive, tinjau modul yang diusulkan. Mode Custom membolehkan pemilihan langsung. Checklist seluler menggunakan tab khusus. Untuk analisis file, pilih file teknis dengan picker atau drag-and-drop. Untuk kerentanan, masukkan vendor, produk dan versi yang telah diperiksa atau jalankan inventaris Windows terlebih dahulu.
4. Mulai pemeriksaan dan tinjau progres serta catatan. Batalkan jika ruang lingkup berubah. Sesi dan bukti dapat dibuka dari Riwayat. Catat tindak lanjut sebelum mengekspor dan menutup sesi.

Dashboard menampilkan hitungan lokal, penggunaan CPU/RAM, pembaruan katalog, ruang disk dan status pemeriksaan API. Tombol API hanya menguji origin HTTPS yang dimasukkan operator. Daftar aset, bukti, dan file tidak dikirim.

CLI menyediakan `asset-add`, `inspect`, `show`, `summary`, `lookup`, `intel-import`, `report`, `verify-audit`, `backup`, dan `restore`. Gunakan `--db PATH` sebelum subcommand untuk memilih database. File JSON pemeriksaan memakai objek `authorization` dan daftar opsional `files`, `checks`, `indicators`, `products`, serta `engines`. Validasi input mengikuti skema `desktop/src/sentinel_inspector/models.py`; jalur file harus absolut dan lokal.

## Pemulihan dan sinkronisasi

Jika proses pemeriksaan berhenti mendadak, pilih sesi dari riwayat dan tekan **Pulihkan sesi terputus**, atau jalankan `sentinel-inspector --db PATH recover ID_SESI`. Status menjadi siap ditinjau. Modul yang belum selesai ditandai gagal, sedangkan hasil dan bukti dari modul selesai dapat diperiksa dan diekspor. Hentikan versi Desktop lama sebelum upgrade supaya semua pemeriksaan aktif memakai kunci sesi yang sama.

Untuk mengirim ringkasan ke unit, tutup sesi dan minta administrator membuat klien API dengan scope `threat.desktop.upload`. Kode aset harus cocok dengan inventaris web. Gunakan origin HTTPS unit. `--ca` menerima sertifikat CA institusi dalam format PEM.

```sh
sentinel-inspector --db PATH sync ID_SESI --revision 1 --url https://sentinel.unit.example --client-id 3 --ca ROOT_CA.pem
```

Perintah meminta rahasia klien saat dijalankan dan hanya mengirim kode aset, nomor revisi, hash laporan, serta hitungan pemeriksaan. Pengiriman revisi yang sama dapat diulang. Ringkasan muncul pada rincian inventaris aset.
