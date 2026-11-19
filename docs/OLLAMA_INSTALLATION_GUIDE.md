# Instalasi Ollama

Instal rilis Ollama yang didukung dari kanal resmi, periksa checksum artefak, dan jalankan pada IP loopback. Tinjau lisensi serta kebutuhan model sebelum administrator mengunduhnya. Pertahankan penyimpanan model pada volume pribadi. Pisahkan akses unduh saat provisioning dari proses layanan operasional. [Ollama](https://ollama.com/download)

Pada lingkungan uji yang terotorisasi, administrator dapat menyiapkan model demonstrasi berikut.

```sh
ollama pull qwen2.5:0.5b
ollama pull nomic-embed-text:latest
```

Jalankan `ollama serve` dengan `OLLAMA_HOST=127.0.0.1:11434` dan `OLLAMA_NO_CLOUD=1` jika didukung rilis. Batasi egress runtime setelah provisioning. Gunakan UI AI Model Manager untuk menyetujui digest instalasi dan lisensi. Gateway menolak model dengan metadata remote, termasuk alias.
