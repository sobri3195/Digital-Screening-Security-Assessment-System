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

Sinkronisasi CISA KEV hanya merekonsiliasi keanggotaan setelah jumlah entri sesuai metadata, seluruh entri valid dan unik, serta tanggal rilis tidak mendahului snapshot terakhir. CVE yang keluar dari katalog tetap dapat ditemukan di detail kerentanan. Riwayat keanggotaan menyimpan bukti dan ID job untuk audit.

## Riwayat NVD dan tindak lanjut

Aktifkan provider NVD lalu jalankan `php bin/threat.php nvd-backfill 1999-01-01 2026-01-01` dengan rentang tanggal publikasi UTC yang dibutuhkan. Job memecah rentang menjadi jendela maksimal 119 hari, menyimpan cursor setiap halaman, dan memakai retry worker. Pantau ID job pada Data Collection Monitor. Gunakan API key resmi bila diperlukan untuk kapasitas yang disetujui.

`php bin/threat.php tick` juga mengevaluasi batch kerentanan terhadap inventaris lokal. Kandidat perlu triase petugas. Peninjau berizin dapat menautkan atau melepas CVE dari insiden melalui detail kerentanan.

Untuk impor terjadwal dari salinan yang dikelola operator, gunakan `php bin/threat.php advisory-import bssn rss /path/salinan.xml` atau ganti `bssn` dengan `kemkes`. Perintah memakai parser dan validasi domain penerbit yang sama dengan formulir upload. Pasok salinan RSS, Atom, atau HTML dari proses akuisisi institusi yang telah diotorisasi.
