# REST API

Referensi mesin tersedia di [openapi.yaml](openapi.yaml). Seluruh endpoint berada di bawah `/api/v1`. Gunakan HTTPS.

- `GET /health` memeriksa koneksi database.
- `POST /auth/token` menerima `client_id` dan `client_secret` dalam JSON. Token berlaku 3600 detik.
- `GET /assets`, `/inspections`, `/checklists`, `/findings`, dan `/reports` memerlukan `Authorization: Bearer …` dan scope `<nama endpoint>.read`. Hasil laporan terbatas pada laporan disetujui.
- Kirim `?after=<ID>` untuk melanjutkan hingga `next_after` bernilai null. Maksimum satu halaman adalah 100 baris.
- Status 401 berarti autentikasi gagal, 403 berarti scope tidak tersedia, 422 berarti masukan tidak valid, dan 429 berarti batas permintaan tercapai.
