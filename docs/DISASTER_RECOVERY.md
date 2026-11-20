# Pemulihan bencana SENTINEL

Gunakan prosedur ini untuk memulihkan satu deployment ke host kosong. Siapkan checkout versi sumber, MariaDB atau MySQL yang kompatibel, klien dump yang sesuai, GnuPG, dan ruang staging milik operator dengan izin privat. Simpan `APP_KEY`, konfigurasi layanan, token workstation, dan kunci dekripsi melalui escrow institusi. Model AI dapat diprovisikan ulang dari artefak lokal dengan digest yang sudah disetujui.

## Buat cadangan

1. Hentikan penulisan dari web, scheduler TI, pemeliharaan, dan layanan yang memakai database terkait. Tunda penghapusan file selama proses backup.
2. Siapkan direktori privat baru dan gunakan file opsi klien database yang hanya dapat dibaca operator. Dump skema aplikasi beserta data ke direktori tersebut. Simpan juga direktori storage, termasuk file privat dan identitas unit bila ada.

```bash
set -euo pipefail
umask 077
stage=$(mktemp -d)
mariadb-dump --defaults-extra-file="$source_client" --single-transaction --hex-blob \
  --skip-add-drop-table "$source_db" > "$stage/database.sql"
cp -a storage "$stage/storage"
```

3. Untuk instalasi yang memakai Desktop atau AI, simpan snapshot setiap SQLite dengan API backup agar halaman WAL ikut tercakup. Beri nama file unik untuk setiap workstation.

```sh
python3 - "$source_sqlite" "$stage/inspector.sqlite3" <<'PY'
from contextlib import closing
from pathlib import Path
import sqlite3
import sys

source = Path(sys.argv[1]).resolve(strict=True)
with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as conn:
    with closing(sqlite3.connect(sys.argv[2])) as snapshot:
        conn.backup(snapshot)
PY
```

4. Arsipkan seluruh staging, lalu tanda tangani dan enkripsi untuk penerima backup yang telah disetujui. Catat commit, deployment, waktu backup, dan fingerprint penandatangan di inventaris cadangan. Setelah verifikasi, bersihkan staging plaintext sesuai prosedur penyimpanan institusi.

```bash
set -euo pipefail
tar -C "$stage" -cf - . | gpg --local-user "$signer" --recipient "$recipient" \
  --sign --encrypt --output "$encrypted_backup"
```

## Pulihkan dan verifikasi

1. Siapkan database baru yang kosong, akun layanan yang hanya diberi akses ke database itu, dan checkout SENTINEL baru. Orang yang menjalankan restore harus memiliki kunci backup dan fingerprint penandatangan yang diperoleh melalui inventaris tepercaya.
2. Dekripsi di staging privat. Lanjutkan hanya jika dekripsi berhasil dan status `VALIDSIG` cocok dengan fingerprint penandatangan yang diharapkan. Periksa daftar isi arsip sebelum mengekstraknya. Impor dump ke database kosong.

```bash
set -euo pipefail
umask 077
restore=$(mktemp -d)
gpg --status-fd 1 --output "$restore/archive.tar" --decrypt "$encrypted_backup" > "$restore/gpg.status"
awk -v signer="$signer" '$2 == "VALIDSIG" && ($3 == signer || $NF == signer) { valid=1 } END { exit !valid }' "$restore/gpg.status"
mkdir "$restore/data"
tar -tf "$restore/archive.tar"
tar -xf "$restore/archive.tar" -C "$restore/data"
mariadb --defaults-extra-file="$target_client" "$target_db" < "$restore/data/database.sql"
```

3. Tempatkan storage pada checkout baru. Pulihkan `APP_KEY` dari escrow, arahkan konfigurasi ke database baru, dan gunakan `APP_UNIT` yang sama jika backup terikat. Pulihkan SQLite ke lokasi baru sebelum menyalakan Desktop dan gateway. Gunakan `PRAGMA integrity_check` dan `PRAGMA foreign_key_check` pada masing-masing snapshot. Untuk Desktop, jalankan `sentinel-inspector --db PATH verify-audit`.
4. Gunakan direktori sesi PHP kosong. Cabut sesi web dan token API lama pada database pulihan, lalu uji login, penerbitan token baru, kecocokan hash unggahan privat, laporan final, catatan audit, dan data katalog TI. Uji dokumen yang telah disetujui di gateway AI serta pembukaan laporan final Desktop jika kedua modul itu dipakai.
5. Catat data yang berhasil dipulihkan dan waktu pemulihan. Arahkan trafik ke host hasil restore setelah pemeriksaan lulus.

Cabut sesi dan token pada database pulihan sebelum layanan dibuka.

```sh
mariadb --defaults-extra-file="$target_client" "$target_db" \
  -e 'DELETE FROM user_sessions; DELETE FROM api_tokens;'
```

## Hasil uji lokal

Arsip sintetis bertanda tangan dan terenkripsi berhasil dipulihkan ke instance MariaDB 11.8 yang baru. Pengujian membandingkan jumlah baris dan hash snapshot laporan, memverifikasi hash unggahan privat, lalu menguji login, PDF, TI, dan penerbitan token API melalui HTTP. Dua snapshot SQLite lulus pemeriksaan integritas dan foreign key. Rantai audit dan revisi final Desktop serta dokumen berstatus disetujui dan indeks pencarian AI juga lulus.
