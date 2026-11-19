# Hasil pengujian Fase 6

| Pemeriksaan | Hasil aktual |
| --- | --- |
| Gateway pada Linux | 10 pytest lulus. Satu uji live dilewati karena model tidak diprovisikan pada lingkungan tersebut. |
| Ollama nyata di GitHub Actions | Lulus pada commit `00be616` dengan Qwen 2.5 0.5B dan Nomic Embed Text. Uji mencakup digest, `/api/show`, embedding, FAISS hybrid, streaming terstruktur, sitasi, dan review. |
| PHP ke gateway FastAPI | 35 pemeriksaan HTTP lulus. Mencakup RBAC, CSRF, HMAC, routing, salah format, abstensi, dan ekspor JSON. |
| Regresi web | 124 pemeriksaan HTTP Fase 1, 37 unit/integrasi Fase 2, dan 62 pemeriksaan HTTP Fase 2 lulus. |
| Desktop | 21 tes Linux lulus dan uji native Windows sebelumnya dilewati. Smoke PySide6 ke gateway aktual lulus untuk token, persetujuan, antrean dan abstensi. |
| Data katalog | Draf CISA KEV yang diekspor dari Fase 2 lulus validasi input gateway. |

Uji keamanan mencakup token kedaluwarsa, scope kurang, payload pribadi atau asing, URL dengan kredensial, sumber yang tidak disetujui, pemisahan tugas, prompt injection pada teks dokumen, penolakan output yang tidak grounded, model berubah, alias remote, dan pembatalan antrean. Evaluasi atas korpus QA pada suite lokal meloloskan dua kasus retrieval. Efektivitas model Bahasa Indonesia pada data produksi belum diukur.

Artefak `local-ollama-metrics` berisi ukuran hardware host, waktu pemuatan, waktu token pertama, kecepatan token, latensi worker, VRAM runtime yang tersedia, dan metrik retrieval yang diukur. [Run dan artefak CI](https://github.com/sobri3195/Digital-Screening-Security-Assessment-System/actions/runs/44439764899#artifacts)

Cloud lokal memverifikasi checksum distribusi Ollama. Runtime di sana memerlukan direktori home yang dapat ditulis dan registry model mengembalikan 403. Inferensi nyata dan benchmark dilaksanakan pada runner terpisah menggunakan distribusi yang sama dan model QA yang diprovisikan secara eksplisit. Pengujian air-gap penuh, Sentence Transformers opsional, GPU organisasi, build Windows desktop Fase 6, dan regresi Fase 3/5 masih belum dilakukan.
