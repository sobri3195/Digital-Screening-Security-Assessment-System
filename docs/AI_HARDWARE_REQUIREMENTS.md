# Kapasitas dan benchmark

Dashboard membaca CPU, jumlah core, RAM tersedia dan ruang disk. Metrik runner meliputi waktu pemuatan, waktu token pertama, token output, token per detik, dan VRAM yang dilaporkan Ollama bila tersedia. Gunakan benchmark pada model yang telah disetujui untuk memilih batas konteks dan concurrency. Angka CI menggambarkan satu host dan snapshot model. Penggunaan GPU aktual serta kapasitas produksi masih memerlukan pengukuran setempat.

Gunakan profil CPU ketika GPU belum disetujui. Jalankan benchmark dengan cold start dan kemudian warm start untuk membedakan biaya pemuatan. Catat konfigurasi dan digest model bersama metrik. [Metrik benchmark dan retrieval CI](https://github.com/sobri3195/Digital-Screening-Security-Assessment-System/actions/runs/44439764899#artifacts)
