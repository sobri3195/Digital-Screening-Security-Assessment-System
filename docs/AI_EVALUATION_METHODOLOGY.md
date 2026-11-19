# Evaluasi AI

Evaluasi bawaan mengambil dua kasus ketersediaan referensi, satu CVE yang harus tersedia dan satu yang harus absen, melalui indeks lokal. Hasil adalah jumlah kasus sesuai corpus yang dipakai. Tes integrasi mengukur validasi sitasi, angka, abstensi, penolakan tipe, digest drift, kontrol injeksi dan response time. Alur live memeriksa embedding nyata, FTS5/FAISS, inferensi JSON, metrik, serta review.

Benchmark skala ini belum mengukur akurasi model produksi. Perbandingan lintas model, benchmark tanpa RAG, analisis recall/precision pada corpus luas, dan uji kualitas Bahasa Indonesia memerlukan dataset referensi yang sudah mendapat persetujuan.
