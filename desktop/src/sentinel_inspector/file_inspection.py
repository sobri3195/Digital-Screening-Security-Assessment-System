from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import md5, sha1, sha256
from pathlib import Path, PurePosixPath
import os
import stat
import struct
from threading import Event
from typing import Callable
from zipfile import BadZipFile, ZipFile

from .database import InspectorError
from .models import Finding, Observation

MAX_FILE = 512 * 1024 * 1024
MAX_DIRECTORY = 8 * 1024 * 1024
CHUNK = 1024 * 1024
MEDIA = {
    "pdf": ("application/pdf", {".pdf"}),
    "pe": ("application/vnd.microsoft.portable-executable", {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl"}),
    "zip": ("application/zip", {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".odt"}),
    "apk": ("application/vnd.android.package-archive", {".apk"}),
    "png": ("image/png", {".png"}),
    "jpeg": ("image/jpeg", {".jpeg", ".jpg"}),
    "text": (
        "text/plain",
        {
            ".txt",
            ".csv",
            ".ps1",
            ".py",
            ".sh",
            ".bat",
            ".cmd",
            ".ini",
            ".cfg",
            ".yaml",
            ".yml",
            ".xml",
            ".json",
            ".log",
            ".conf",
        },
    ),
}


class Cancelled(InspectorError):
    pass


def check_cancel(cancel: Event):
    if cancel.is_set():
        raise Cancelled("Pemeriksaan dibatalkan.")


def path_stat(path: Path):
    if not path.is_absolute() or str(path).startswith(("//", "\\\\")):
        raise InspectorError("Pilih file biasa melalui jalur lokal absolut.")
    if os.name == "nt":
        import ctypes

        if any(":" in part for part in path.parts[1:]) or ctypes.windll.kernel32.GetDriveTypeW(
            str(path.anchor)
        ) not in (2, 3, 5, 6):
            raise InspectorError("Pilih file pada volume lokal, tanpa alternate data stream.")
        try:
            for parent in path.parents:
                if getattr(parent.lstat(), "st_file_attributes", 0) & 0x400:
                    raise InspectorError("Jalur melalui reparse point tidak didukung.")
        except OSError as error:
            raise InspectorError("Jalur file tidak dapat divalidasi.") from error
    try:
        result = path.lstat()
    except OSError as error:
        raise InspectorError("File pilihan tidak dapat dibaca.") from error
    if not stat.S_ISREG(result.st_mode) or getattr(result, "st_file_attributes", 0) & 0x400:
        raise InspectorError("Symlink, reparse point, perangkat, dan direktori tidak didukung.")
    return result


@contextmanager
def open_selected(path: Path, maximum: int = MAX_FILE):
    original = path_stat(path)
    if original.st_size > maximum:
        raise InspectorError("Ukuran file melampaui batas pemeriksaan.")
    flags = (
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise InspectorError("File pilihan tidak dapat dibuka.") from error
    with os.fdopen(fd, "rb") as handle:
        current = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(original, current)
            or current.st_size > maximum
        ):
            raise InspectorError("File berubah sebelum dapat diperiksa.")
        try:
            yield handle, current
        finally:
            final = os.fstat(handle.fileno())
            if (final.st_mtime_ns, final.st_size) != (current.st_mtime_ns, current.st_size):
                raise InspectorError("File berubah selama pemeriksaan. Bukti diabaikan.")


@dataclass(frozen=True)
class Metadata:
    name: str
    size: int
    extension: str
    kind: str
    hashes: dict
    magic: str
    structural_issue: str | None
    archive: dict | None

    def observation(self) -> Observation:
        mime, suffixes = MEDIA.get(self.kind, ("application/octet-stream", set()))
        mismatch = (
            bool(suffixes)
            and bool(self.extension)
            and self.extension not in suffixes
            and not (self.kind == "zip" and self.extension == ".apk")
        )
        known_suffix = any(self.extension in allowed for _, allowed in MEDIA.values())
        mismatch = mismatch or (self.kind == "unknown" and known_suffix)
        notices = []
        if mismatch or self.structural_issue:
            notices.append(
                Finding(
                    "suspicious_file_signature",
                    "Jenis berkas perlu diverifikasi",
                    "low",
                    "Tinjau signature, struktur, dan ekstensi pada salinan yang diotorisasi. Perbedaan jenis bukan bukti malware.",
                )
            )
        if self.archive and self.archive["unsafe_names"]:
            notices.append(
                Finding(
                    "archive_structure",
                    "Arsip memuat nama entri yang perlu ditinjau",
                    "medium",
                    "Periksa struktur di lingkungan terkendali sebelum membuka atau mengekstrak arsip.",
                )
            )
        return Observation(
            "Signature file dan hashlib",
            {
                "filename": self.name,
                "size": self.size,
                "extension": self.extension,
                "format": self.kind,
                "mime": mime,
                "magic": self.magic,
                "hashes": self.hashes,
                "extension_mismatch": mismatch,
                "structure_notice": self.structural_issue,
                "archive": self.archive,
            },
            tuple(notices),
        )


def hashes(handle, expected: int, cancel: Event, progress: Callable[[int, int], None]) -> dict:
    digests = {"md5": md5(usedforsecurity=False), "sha1": sha1(usedforsecurity=False), "sha256": sha256()}
    measured = 0
    while True:
        check_cancel(cancel)
        block = handle.read(CHUNK)
        if not block:
            break
        measured += len(block)
        if measured > expected:
            raise InspectorError("Ukuran file berubah selama pembacaan.")
        for algorithm in digests.values():
            algorithm.update(block)
        progress(measured, expected)
    if measured != expected:
        raise InspectorError("Pembacaan file tidak lengkap.")
    return {name: calculator.hexdigest() for name, calculator in digests.items()}


def signature(prefix: bytes) -> tuple[str, str | None]:
    if prefix.startswith(b"%PDF-"):
        return "pdf", None if len(prefix) >= 8 else "Header PDF tidak lengkap."
    if prefix.startswith(b"MZ"):
        if len(prefix) < 64:
            return "unknown", "Header MZ tidak lengkap."
        pe = struct.unpack_from("<I", prefix, 0x3C)[0]
        if pe >= 64 and prefix[pe : pe + 4] == b"PE\0\0":
            return "pe", None
        return "unknown", "Signature PE tidak terbaca pada batas header 64 KiB."
    if prefix[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip", None
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", None
    if prefix.startswith(b"\xff\xd8\xff"):
        return "jpeg", None
    if prefix and b"\x00" not in prefix:
        try:
            prefix.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        else:
            if sum(byte < 32 and byte not in (9, 10, 13) for byte in prefix) < max(1, len(prefix) // 20):
                return "text", None
    return "unknown", None


@contextmanager
def bounded_zip(handle, size: int):
    if size < 22:
        raise InspectorError("Struktur akhir ZIP tidak ditemukan.")
    handle.seek(max(0, size - 65557))
    tail = handle.read()
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise InspectorError("Struktur akhir ZIP tidak ditemukan.")
    disk, central_disk, disk_count, count, directory_size, central_offset, comment_len = struct.unpack_from(
        "<HHHHIIH", tail, offset + 4
    )
    if (
        disk
        or central_disk
        or disk_count != count
        or count > 10000
        or directory_size > MAX_DIRECTORY
        or directory_size + central_offset > size
        or offset + 22 + comment_len != len(tail)
    ):
        raise InspectorError("Direktori ZIP terlalu besar, tersegmentasi, atau tidak konsisten.")
    try:
        with ZipFile(handle) as archive:
            if len(archive.infolist()) != count:
                raise InspectorError("Jumlah entri ZIP tidak konsisten.")
            yield archive
    except (BadZipFile, NotImplementedError, RuntimeError) as error:
        raise InspectorError("Direktori ZIP tidak dapat divalidasi.") from error


def inspect(
    path: Path, cancel: Event, progress: Callable[[int, int], None] = lambda done, total: None
) -> Metadata:
    with open_selected(path) as (handle, info):
        prefix = handle.read(65536)
        handle.seek(0)
        checksums = hashes(handle, info.st_size, cancel, progress)
        kind, issue = signature(prefix)
        directory = None
        if kind == "zip":
            try:
                with bounded_zip(handle, info.st_size) as archive:
                    entries = archive.infolist()
                    names = [entry.filename for entry in entries]
                    unsafe = 0
                    for name in names:
                        normalized = PurePosixPath(name.replace("\\", "/"))
                        if (
                            normalized.is_absolute()
                            or ".." in normalized.parts
                            or (normalized.parts and ":" in normalized.parts[0])
                        ):
                            unsafe += 1
                    directory = {
                        "entries": len(entries),
                        "unsafe_names": unsafe,
                        "encrypted_entries": sum(bool(entry.flag_bits & 1) for entry in entries),
                        "reported_uncompressed_bytes": sum(entry.file_size for entry in entries),
                    }
                    if "AndroidManifest.xml" in names:
                        kind = "apk"
            except InspectorError as error:
                issue = str(error)
        return Metadata(
            path.name[:240],
            info.st_size,
            path.suffix.lower(),
            kind,
            checksums,
            prefix[:8].hex(" ") if kind in ("pdf", "pe", "zip", "apk", "png", "jpeg") else "",
            issue,
            directory,
        )
