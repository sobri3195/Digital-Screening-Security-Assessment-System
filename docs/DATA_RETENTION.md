# Retensi data

| Data | Periode operasional |
| --- | --- |
| Isi file pemeriksaan | 30 hari. Metadata dan hash tetap tersedia. |
| Riwayat percobaan login | 90 hari. |
| Sesi kedaluwarsa dan bucket pembatasan | Dibersihkan setelah 1 hari. |
| Token API | Masa berlaku 1 jam. Hapus token kedaluwarsa melalui pemeliharaan. |
| Backup aplikasi | 30 hari. |
| Temuan, insiden, laporan, audit | Pengelola menetapkan jadwal menurut kebijakan institusi. |

Jalankan `php bin/maintenance.php retention` minimal harian. Penghapusan pada level aplikasi menghapus berkas dari filesystem. Untuk retensi dan penghapusan pada media SSD, snapshot, atau cadangan eksternal, gunakan mekanisme perangkat dan kebijakan penyimpanan institusi.
