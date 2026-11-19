# Basis pengetahuan

Impor objek JSON teknis dengan `title`, `source`, `version`, `published`, `reference`, `classification`, `content`, dan `facts`. Gunakan sumber CISA, NIST, FIRST, MITRE, OWASP, BSSN, Kemenkes, vendor yang diizinkan, atau referensi internal `REF-...`. Pastikan dokumen tidak memuat PII atau rahasia sebelum mengajukan. Peninjau berbeda memeriksa teks, struktur fakta, lisensi, rujukan dan checksum sebelum menyetujui. Setelah arsip atau penonaktifan sumber, dokumen dikeluarkan dari hasil pencarian aktif.

Ekspor draf fakta CVE yang sudah disimpan Fase 2 dengan `php bin/threat-ai-export.php CVE-2021-44228`. Hasil berupa daftar dokumen yang memisahkan CISA, NIST, dan FIRST jika observasi masing-masing tersedia. Ajukan satu objek per dokumen. Admin dapat mengaktifkan indeks embedding setelah persetujuan atau secara terpisah melalui RAG Management.
