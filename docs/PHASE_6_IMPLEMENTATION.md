# PUSKESAU SENTINEL Fase 6

SENTINEL AI Engine 3.0.0 menambah FastAPI, SQLite, antrean asinkron, Ollama, indeks kata kunci FTS5 dan vektor FAISS. Branch dasar memuat source web Fase 1 dan 2 serta desktop Fase 4. Source Fase 3 dan 5 tidak ditemukan sebagai tahap terpisah. Modul sebelumnya tetap dapat beroperasi ketika gateway atau runtime berhenti.

## Perubahan

| Area | Lokasi |
| --- | --- |
| Gateway, runtime, worker, dan validasi | `ai-engine/src/sentinel_ai/` |
| Migrasi | `ai-engine/src/sentinel_ai/migrations/001_initial.sql` dan seed idempoten `app/Services/Ai/Setup.php` |
| Web dan API | `app/Controllers/Ai.php`, `app/Views/ai.php`, `app/Services/Ai/Gateway.php` |
| Desktop | `desktop/src/sentinel_inspector/ai_panel.py`, `ai_client.py` |
| Ekspor rujukan Fase 2 | `bin/threat-ai-export.php` |
| Uji dan CI | `ai-engine/tests/`, `tests/smoke_ai_web.py`, `.github/workflows/sentinel-ai.yml` |

AI memilih fakta dan tindakan defensif dari daftar yang dibentuk oleh aplikasi. Teks hasil, sitasi, nilai CVSS/EPSS, dan hitungan tetap dirangkai server dari metadata terverifikasi. Jika rujukan yang berlaku tidak tersedia, gateway mengembalikan abstensi dan tidak memanggil model. Gangguan model, output yang gagal validasi, dan perubahan digest menghasilkan status gagal.

## Operasi dan batasan

- [Arsitektur dan aliran data](AI_ENGINE_ARCHITECTURE.md)
- [Instalasi Ollama](OLLAMA_INSTALLATION_GUIDE.md), [konfigurasi model](AI_MODEL_CONFIGURATION.md), dan [kebutuhan host](AI_HARDWARE_REQUIREMENTS.md)
- [Integrasi model](LOCAL_LLM_INTEGRATION.md), [RAG](RAG_ENGINE_GUIDE.md), dan [pengelolaan pengetahuan](KNOWLEDGE_BASE_MANAGEMENT.md)
- [Endpoint](AI_API_DOCUMENTATION.md), [panduan web dan desktop](AI_SECURITY_ASSISTANT_GUIDE.md), serta [deployment](AI_DEPLOYMENT_GUIDE.md)
- [Analisis](AI_THREAT_ANALYSIS.md), [mitigasi](AI_MITIGATION_METHODOLOGY.md), dan [laporan](AI_REPORT_GENERATION.md)
- [Privasi](AI_PRIVACY_POLICY.md), [keamanan](AI_SECURITY_POLICY.md), dan [proteksi prompt injection](PROMPT_INJECTION_PROTECTION.md)
- [Evaluasi](AI_EVALUATION_METHODOLOGY.md) dan [hasil pengujian](PHASE_6_TEST_REPORT.md)

Model QA berskala kecil memvalidasi jalur inferensi. Untuk mengukur mutu produksi, jalankan perbandingan model terhadap suite institusi yang disetujui. Pengguna berizin dapat mengajukan profil template bawaan dan peninjau berbeda menyetujui aktivasi. Web menampilkan tahap tugas secara berkala dan API mendukung peristiwa SSE. Referensi CVE dari Fase 2 dapat dibuat menjadi draf dari halaman Knowledge Base. Draf mengikuti review sumber dan klasifikasi sebelum masuk pencarian aktif. [Evaluasi model](AI_EVALUATION_METHODOLOGY.md) · [API dan peninjauan](AI_API_DOCUMENTATION.md)
