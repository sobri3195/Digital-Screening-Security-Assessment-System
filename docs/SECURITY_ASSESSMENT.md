# Penilaian keamanan Fase 2

Akses web memakai RBAC dan CSRF yang sudah ada. Riwayat pemindaian dan draf laporan dibatasi pemilik, dengan akses peninjauan laporan terpisah untuk supervisor. Token REST dan scope wajib. Query menggunakan parameter terikat, keluaran HTML di-escape, dan PDF memakai konfigurasi Dompdf dengan akses jaringan dinonaktifkan. Indikator URL ditampilkan defanged dan query disunting dari tampilan serta riwayat.

Koneksi feed hanya berasal dari worker dan menuju endpoint HTTPS tetap. cURL memverifikasi sertifikat, melarang redirect, membatasi koneksi dan ukuran respons, serta memakai kunci hanya untuk provider yang memilikinya. Parser XML/HTML memblokir DTD, entitas eksternal, dan akses jaringan. Sistem tidak menghubungi target masukan, mengeksekusi file, atau mengunduh sampel.

Gunakan pemeliharaan retensi dan aturan egress. Restore Fase 1 mempertahankan relasi temuan aset TI jika pasangan ID/kode aset kompatibel. Cadangan operasional Fase 1 tidak mencakup tabel TI, sehingga operator perlu mencadangkan skema TI secara terpisah. Review keamanan independen, pemulihan bencana, dan tuning produksi masih diperlukan.
