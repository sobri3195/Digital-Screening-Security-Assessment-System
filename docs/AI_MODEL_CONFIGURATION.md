# Konfigurasi model

Model terpasang muncul dari Ollama. Administrator menyetujui nama persis dan referensi lisensi untuk peran inference atau embedding. Persetujuan menyimpan digest instalasi. Pilih maksimal satu model aktif untuk tiap peran. Saat runtime tidak cocok, setujui digest baru setelah peninjauan. Ollama model lokal dari keluarga yang kompatibel dapat dipilih tanpa mengunci ke satu vendor.

Atur context 1.024–8.192, temperature, top P, output 64–512 token, dan CPU atau auto. Kontrol timeout dan concurrency memakai environment server. Penggunaan GPU bergantung pada runtime dan driver. Tidak ada pemilihan model default. QA mencakup Qwen 2.5 0.5B dan Nomic Embed Text, keduanya model uji, dengan lisensi yang harus ditinjau sebelum deployment. [Qwen 2.5](https://ollama.com/library/qwen2.5) · [Nomic Embed Text](https://ollama.com/library/nomic-embed-text)
