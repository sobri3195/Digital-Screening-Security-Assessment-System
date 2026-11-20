# Evaluasi AI

Evaluasi bawaan mengambil dua kasus ketersediaan referensi, satu CVE yang harus tersedia dan satu yang harus absen, melalui indeks lokal. Hasil adalah jumlah kasus sesuai corpus yang dipakai. Tes integrasi mengukur validasi sitasi, angka, abstensi, penolakan tipe, digest drift, kontrol injeksi dan response time. Alur live memeriksa embedding nyata, FTS5/FAISS, inferensi JSON, metrik, serta review.

Benchmark skala ini belum mengukur akurasi model produksi. Perbandingan lintas model, benchmark tanpa RAG, analisis recall/precision pada corpus luas, dan uji kualitas Bahasa Indonesia memerlukan dataset referensi yang sudah mendapat persetujuan.

## Bandingkan model yang telah disetujui

Siapkan suite JSON berisi 1–20 permintaan teknis yang lolos skema gateway. Gunakan kasus dengan jawaban berreferensi dan kasus yang membutuhkan abstensi. `references` berisi ID dokumen pembanding yang sudah disetujui. `terms` memuat istilah Indonesia yang diperiksa pada ringkasan dan rekomendasi. Contoh minimal memakai CVE sintetis.

```json
{"cases":[{"id":"rujukan-absen","request":{"kind":"vulnerability","cve":"CVE-9999-999999999"},"expected":"abstain","terms":["Bukti belum cukup"]}]}
```

```sh
sentinel-ai evaluate suite.json --model ID_MODEL_PERTAMA --model ID_MODEL_KEDUA > hasil-evaluasi.json
```

Output mencatat hash suite, digest model, cakupan rujukan dari baseline keyword, kesesuaian abstensi, sitasi yang diharapkan, kecocokan istilah, dan metrik waktu. Tambahkan `--internal` untuk suite dengan referensi internal yang disetujui. Jalankan di host uji lokal dengan konfigurasi SQLite dan runtime yang ingin diukur. Penilaian manusia tetap diperlukan untuk kualitas bahasa dan ketepatan makna. Pengujian institusi memerlukan target latensi serta corpus yang disetujui.
