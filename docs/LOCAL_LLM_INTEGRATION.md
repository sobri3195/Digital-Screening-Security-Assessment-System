# Integrasi model lokal

Gateway hanya memakai Ollama pada IP loopback dengan endpoint tetap `/api/tags`, `/api/show`, `/api/ps`, `/api/embed`, dan `/api/generate`. Verifikasi kecocokan digest dan metadata lokal dilakukan sebelum dan setelah inferensi. Streaming NDJSON diproses server untuk waktu token pertama dan pengukuran runtime. Nilai mentah sebelum validasi tidak dikirim ke operator.

Input inferensi memakai proyeksi fakta terstruktur. Output yang diterima hanya daftar ID fakta dan tindakan yang diizinkan. Infrastruktur tidak menyediakan layanan cloud ataupun tindakan otomatis. Jalankan pengujian live dengan model lokal yang telah diprovisikan dan variabel `AI_LIVE_TEST`, `AI_LIVE_INFERENCE_MODEL` dan `AI_LIVE_EMBEDDING_MODEL`.
