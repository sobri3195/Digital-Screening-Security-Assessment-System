# Kebijakan keamanan AI

Tempatkan Ollama dan gateway di server internal. Terapkan segmentasi, pembatasan egress model, token singkat PHP serta token workstation ber-scope minimal. Persetujuan model memerlukan pemeriksaan digest dan lisensi. Gateway memeriksa metadata model sehingga alias yang melaporkan remote host atau remote model ditolak. Letakkan service gateway di balik HTTPS reverse proxy bila digunakan lintas host. Buat backup SQLite memakai mekanisme konsisten yang terenkripsi dan lakukan uji pemulihan sesuai kebijakan organisasi.

Batasi CPU, RAM, ukuran request, waktu job, concurrency dan kapasitas indeks sesuai hasil pengujian host. Uji ulang setelah memperbarui runtime, embedding, corpus atau template. Output AI membutuhkan peninjauan manusia.
