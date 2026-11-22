# MARGONO AI Engine

Gateway FastAPI 3.0.0 untuk analisis teknis lokal. Gunakan Python 3.12 dan jalankan dari root repository.

```sh
python -m venv .venv-ai
. .venv-ai/bin/activate
python -m pip install -e "./ai-engine[test]"
sentinel-ai serve --port 8766
```

Jalankan Ollama pada loopback dengan model yang telah diperiksa secara administratif. Setelah itu konfigurasikan kredensial web atau token workstation. Pengaturan contoh berada di `.env.example`. Gateway membaca variabel environment proses. Tetapkan juga `AI_GATEWAY_URL` dan `AI_WEB_KEY` pada aplikasi PHP, lalu jalankan `php bin/setup.php migrate`. Tidak ada model yang dipilih atau diunduh saat gateway dimulai.

- [Implementasi, pengoperasian, dan hasil pengujian](../docs/PHASE_6_IMPLEMENTATION.md)
- [Panduan deployment](../docs/AI_DEPLOYMENT_GUIDE.md)
- [API dan scope](../docs/AI_API_DOCUMENTATION.md)
