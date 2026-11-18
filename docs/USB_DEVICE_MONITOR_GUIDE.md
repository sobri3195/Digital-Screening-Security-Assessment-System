# Monitor USB

Mulai pemantauan dari halaman Monitor USB dan hentikan saat pekerjaan selesai. Windows CIM mengembalikan antarmuka PnP USB, model dan produsen bila tersedia, serta kode status driver. Kategori berasal dari teks model, kelas dan layanan driver, sehingga perangkat dengan driver generik mungkin masuk kategori USB lain. Satu perangkat fisik dapat memiliki beberapa antarmuka. Monitor bersifat polling, sehingga koneksi yang lebih singkat daripada interval delapan detik dapat terlewat.

Identitas PnP hanya dipakai untuk deduplikasi dalam memori. Database menyimpan peristiwa dan metadata minimum. Tidak ada pembacaan konten USB, auto-copy, autorun, atau pemberian otorisasi otomatis. Jalankan `sentinel-inspector retain-usb 90` untuk menghapus catatan koneksi lebih lama dari 90 hari bila kebijakan institusi mengizinkan.
