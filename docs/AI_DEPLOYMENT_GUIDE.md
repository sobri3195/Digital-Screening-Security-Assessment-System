# Menjalankan gateway

Siapkan virtual environment Python 3.12, instal `./ai-engine[test]`, dan jalankan `sentinel-ai serve --port 8766`. Linux menggunakan `export AI_...` dan Windows PowerShell `$env:AI_... = 'nilai'`. Tinjau `ai-engine/.env.example` untuk semua pengaturan. Set `AI_DATABASE` pada volume pribadi, `AI_OLLAMA_ORIGIN` pada loopback, dan `AI_WEB_KEY` sebagai hex 32 byte acak. Gunakan `sentinel-ai generate-web-key` melalui kanal lokal aman. Jangan masukkan kunci ke source control.

Untuk web, gunakan kunci yang sama, set `AI_GATEWAY_URL` dan jalankan `php bin/setup.php migrate`. Untuk desktop, buat token dengan `sentinel-ai workstation-token ID ai.dashboard.view ai.analysis.execute ai.vulnerability.analyze`. Serahkan nilai token kepada operator melalui kanal aman dan simpan hanya `registry_entry` dalam array JSON `AI_WORKSTATIONS_FILE`. Restart gateway untuk menerapkan registry yang diperbarui.

Jalankan Ollama dan gateway sebagai akun layanan terpisah. Gunakan port loopback yang berbeda. Host pusat memerlukan reverse proxy HTTPS dengan sertifikat yang mencakup IP internal. Client hanya mengizinkan loopback atau IP privat HTTPS sesuai mode. Tetapkan aturan firewall antarsegmen, batasi egress Ollama setelah provisioning, simpan hash model, serta verifikasi backup dan pemantauan job.
