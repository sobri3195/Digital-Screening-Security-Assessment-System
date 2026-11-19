# API lokal

Gunakan prefix `/api/v1/ai`. Semua endpoint memerlukan Bearer. Kredensial web merupakan delegasi HMAC 60 detik yang dibuat PHP. Desktop langsung ke gateway memakai token workstation hex yang ditetapkan oleh administrator. Respons 401 berarti kredensial salah, 403 berarti scope kurang, 422 berarti body atau tipe analisis salah, 429 berarti batas tugas atau permintaan tercapai, dan 503 berarti runtime tidak tersedia.

| Endpoint | Izin |
| --- | --- |
| GET health, status, models | ai.dashboard.view |
| POST analyze/{threat,vulnerability,malware,configuration,mitigation,correlation,advisory,education} | ai.analysis.execute dan izin tipe |
| POST reports/{generate,summary} | ai.analysis.execute + ai.report.generate, delegasi web |
| GET tasks, tasks/{id}, tasks/{id}/events | Pemilik tugas, atau izin review pada tugas analisis |
| POST tasks/{id}/cancel | Pemilik tugas |
| POST tasks/{id}/review | ai.report.review, peninjau berbeda |
| GET knowledge/sources, knowledge/documents, knowledge/documents/{id}, knowledge/search | ai.knowledge.view, akses draf lebih terbatas |
| POST knowledge/documents | ai.knowledge.manage + ai.knowledge.view |
| POST knowledge/documents/{id}/approve, archive, index | ai.knowledge.approve, untuk index juga ai.knowledge.manage |
| PUT knowledge/sources/{code} | ai.knowledge.manage |
| POST models, models/{id}/activation, models/{id}/benchmark, PUT models/{id}/options | ai.model.manage |
| GET/POST evaluation | ai.evaluation.execute |
| GET templates | ai.template.manage |
| GET audit | ai.audit.view |
| POST settings/retention | ai.settings.manage |

Contoh analisis memakai `{"kind":"vulnerability","cve":"CVE-2021-44228"}`. Respons 202 berisi `id` antrean. Pantau status dan tampilkan hasil yang telah lulus validasi. API PHP untuk bearer Fase 1 hanya meneruskan subset baca dan analisis. API Gateway merupakan rujukan scope penuh. Untuk mengekspor skema lokal, jalankan `python -c "import json; from sentinel_ai.gateway import create_app; print(json.dumps(create_app().openapi()))"` dari environment terkonfigurasi.
