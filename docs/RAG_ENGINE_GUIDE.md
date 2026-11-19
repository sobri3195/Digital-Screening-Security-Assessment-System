# RAG

Approval membuat potongan 130 kata dengan overlap 25 kata dan indeks FTS5. Model embedding lokal yang aktif dapat mengisi vektor dengan job terpisah. Pencarian vektor menggunakan cosine similarity pada FAISS IndexFlatIP dan dokumen yang sudah disetujui. Gateway menyatukan ranking kata kunci, metadata teknis dan kedekatan vektor, lalu membatasi konteks hingga enam referensi. Field CVE dan indikator memakai filter identik sehingga pencarian semantik tidak mengubah target.

Model Ollama embedding atau instalasi Sentence Transformers berbasis safetensors lokal dapat digunakan. Untuk Sentence Transformers, instal ekstra `transformers`, verifikasi digest direktori menggunakan `sentinel-ai embedding-digest PATH`, lalu tetapkan `AI_EMBEDDING_DIR` dan `AI_EMBEDDING_SHA256`. Jalur opsional ini belum diuji dengan model nyata. Ketika indeks vektor tidak tersedia, metode retrieval ditandai keyword.
