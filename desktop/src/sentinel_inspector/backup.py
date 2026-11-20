from hashlib import sha256
from contextlib import closing
import os
from pathlib import Path
from secrets import token_bytes
import sqlite3
from tempfile import TemporaryDirectory

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .database import Database, InspectorError

MAGIC = b"PSI-BKP1"
CAP = 128 * 1024 * 1024


def key(secret: str, salt: bytes) -> bytes:
    if len(secret) < 14 or len(secret) > 200:
        raise InspectorError("Frasa sandi backup harus 14–200 karakter.")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(secret.encode("utf-8"))


def exclusive(path: Path, data: bytes):
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError as error:
        raise InspectorError("File tujuan sudah ada. Pilih nama lain.") from error
    with os.fdopen(descriptor, "wb") as output:
        try:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        except OSError:
            path.unlink(missing_ok=True)
            raise


def create(db: Database, out: Path, secret: str) -> str:
    salt = token_bytes(16)
    nonce = token_bytes(12)
    derived = key(secret, salt)
    with TemporaryDirectory(prefix="sentinel-backup-", dir=db.path.parent) as directory:
        temp = Path(directory) / "snapshot.db"
        with (
            closing(sqlite3.connect(db.path.as_uri() + "?mode=ro", uri=True, timeout=5)) as source,
            closing(sqlite3.connect(temp)) as copy,
        ):
            source.backup(copy)
        if temp.stat().st_size > CAP:
            raise InspectorError("Basis data melampaui batas backup 128 MiB.")
        envelope = MAGIC + salt + nonce + AESGCM(derived).encrypt(nonce, temp.read_bytes(), MAGIC)
    exclusive(out, envelope)
    checksum = sha256(envelope).hexdigest()
    with db.write() as c:
        db.audit(c, None, "backup_created", {"sha256": checksum})
    return checksum


def restore(source: Path, out: Path, secret: str) -> str:
    from .file_inspection import open_selected

    with open_selected(source, CAP + 100) as (handle, _):
        raw = handle.read(CAP + 101)
    if len(raw) < 52 or not raw.startswith(MAGIC):
        raise InspectorError("Format cadangan tidak dikenali.")
    salt, nonce, body = raw[8:24], raw[24:36], raw[36:]
    try:
        plain = AESGCM(key(secret, salt)).decrypt(nonce, body, MAGIC)
    except InvalidTag as error:
        raise InspectorError("Integritas cadangan atau frasa sandi tidak valid.") from error
    if not plain.startswith(b"SQLite format 3\x00") or len(plain) > CAP:
        raise InspectorError("Cadangan bukan snapshot SQLite yang dikenali.")
    with TemporaryDirectory(prefix="sentinel-restore-", dir=out.parent) as directory:
        check = Path(directory) / "validation.db"
        exclusive(check, plain)
        try:
            with closing(sqlite3.connect(check)) as connection:
                connection.execute("PRAGMA trusted_schema=OFF")
                if (
                    connection.execute("PRAGMA user_version").fetchone() not in ((1,), (2,), (3,))
                    or connection.execute("PRAGMA integrity_check").fetchone() != ("ok",)
                    or connection.execute("PRAGMA foreign_key_check").fetchone()
                ):
                    raise InspectorError("Basis data hasil pemulihan belum lolos validasi.")
            database = Database(check)
            try:
                if not database.verify_audit():
                    raise InspectorError("Rantai audit cadangan tidak valid.")
            finally:
                database.engine.dispose()
        except sqlite3.DatabaseError as error:
            raise InspectorError("Basis data hasil pemulihan tidak valid.") from error
    exclusive(out, plain)
    return sha256(raw).hexdigest()
