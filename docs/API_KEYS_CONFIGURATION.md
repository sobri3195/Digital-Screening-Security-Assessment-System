# Konfigurasi kunci API

Tetapkan `TI_NVD_KEY` bila ingin menggunakan akses NVD berautentikasi. `TI_URLHAUS_KEY`, `TI_THREATFOX_KEY`, dan `TI_MALWAREBAZAAR_KEY` diwajibkan untuk adapter terkait. Masukkan nilai lewat secret manager atau environment privat proses PHP CLI; lakukan hal yang sama bagi proses PHP web bila memakai status konfigurasi pada UI. Pada lingkungan lokal, berkas `.env` dapat digunakan sesuai panduan instalasi. Jaga hak baca dan rotasikan sesuai kebijakan institusi.

Kunci dipakai hanya pada endpoint tetap untuk provider masing-masing. UI menampilkan status ketersediaan dan log menyimpan jenis kesalahan, tanpa nilai kunci ataupun isi respons kegagalan. Lihat persyaratan lisensi dan akses institusi sebelum mengaktifkan provider.
