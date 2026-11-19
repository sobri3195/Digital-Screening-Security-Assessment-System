# Arsitektur dan aliran data

```mermaid
flowchart LR
    Web["PHP, sesi, RBAC"] -->|"delegasi HMAC singkat"| Gateway["FastAPI dan scope"]
    Desktop["PySide6 dengan persetujuan operator"] -->|"token workstation"| Gateway
    Gateway --> Queue["Antrean SQLite"]
    Queue --> Worker["Worker dan validasi"]
    Knowledge["Dokumen dan fakta disetujui"] -->|"FTS5 dan FAISS"| Worker
    Worker -->|"proyeksi fakta tanpa teks dokumen"| Ollama["Ollama di loopback"]
    Ollama -->|"JSON ID prioritas"| Worker
    Worker --> Result["Fakta dan sitasi disusun kode"]
    Result --> Review["Tinjauan petugas lain"]
    Review --> PDF["PDF terverifikasi"]
```

Antrean mengikat ID, status, lease, percobaan dan pembatalan pada database khusus. Model tidak mempunyai koneksi ke database web atau antarmuka aksi. Dokumen dan data sumber dipisahkan dari system instruction. Model menerima ID fakta, kategori, nilai numerik, dan opsi tindakan tetap. Aplikasi menyusun sitasi dan rekomendasi setelah memeriksa semua ID. PDF memakai generator PHP yang sama setelah hasil diverifikasi petugas lain.
