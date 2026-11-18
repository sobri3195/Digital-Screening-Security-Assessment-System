# Metodologi skor

Aturan `priority-1` memberi prioritas peninjauan dan menyimpan komponen yang dapat diperiksa. Untuk IOC, gunakan keparahan tertinggi dari bukti yang berlaku (kritis 45, tinggi 35, sedang 24, rendah 12, informasional 5, tidak diketahui 0), ditambah maksimum 20 dari confidence, 10 jika ada observasi terverifikasi, 10 jika ada observasi dalam 30 hari, dan 5 per sumber tambahan hingga 15. Jumlah provider tidak membuktikan independensi.

Untuk CVE, gunakan pembulatan `CVSS × 5`, tambah 30 jika tercatat oleh CISA KEV, lalu pembulatan `EPSS × 20`. Tingkat prioritas dimulai dari 85 (kritis), 65 (tinggi), 40 (sedang), dan 15 (rendah); skor lebih rendah informasional. Nilai keparahan, confidence, EPSS, dan prioritas ditampilkan terpisah. Status verifikasi dan mitigasi aset tetap mengikuti tinjauan petugas.
