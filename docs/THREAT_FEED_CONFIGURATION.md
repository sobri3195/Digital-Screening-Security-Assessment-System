# Konfigurasi feed

| Provider | Data | Jadwal awal | Kunci |
| --- | --- | --- | --- |
| CISA KEV | Katalog resmi CISA melalui repositori resmi `cisagov/kev-data` | 24 jam | Tidak |
| NIST NVD | API CVE 2.0, pembaruan bertahap dan paginasi | 6 jam | Opsional |
| FIRST EPSS | Skor terkini untuk CVE publik yang sudah diimpor dari CISA/NVD | 24 jam | Tidak |
| URLhaus | URL distribusi malware dan metadata status | 6 jam | Ya |
| ThreatFox | Observasi IOC terbaru | 6 jam | Ya |
| MalwareBazaar | Metadata dan hash file terbaru | 6 jam | Ya |
| BSSN dan Kemenkes CSIRT | Input manual dan impor salinan advisori yang diotorisasi | Manual | Tidak |

Pilih provider di Threat Feed Management, jalankan **Uji dan pratinjau**, lalu periksa Data Collection Monitor. Aktifkan jadwal setelah pratinjau berhasil. NVD memuat tujuh hari terakhir pada pengambilan pertama dan melanjutkan dari checkpoint dengan overlap satu menit. EPSS memakai batch CVE yang telah dipublikasikan oleh sumber tersebut. URLhaus, ThreatFox dan MalwareBazaar memerlukan akun yang memberikan akses institusional. Keluaran MalwareBazaar adalah metadata, tanpa sampel.

Pasang aturan egress untuk tujuan tepat yang diperlukan: `raw.githubusercontent.com`, `services.nvd.nist.gov`, `api.first.org`, `urlhaus-api.abuse.ch`, `threatfox-api.abuse.ch`, `mb-api.abuse.ch`. Awasi status provider, tenggat data, dan log antrian. Uji koneksi tidak mengaktifkan jadwal.
