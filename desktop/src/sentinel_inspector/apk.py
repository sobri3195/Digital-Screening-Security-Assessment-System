from pathlib import Path
import re
import struct
from threading import Event
from xml.etree import ElementTree

from cryptography.hazmat.primitives.serialization import pkcs7

from .database import InspectorError
from .file_inspection import bounded_zip, check_cancel, hashes, open_selected
from .models import Finding, Observation

MAX_MEMBER = 1024 * 1024
ANDROID = "{http://schemas.android.com/apk/res/android}"
WANTED = {"package", "versionName", "versionCode", "minSdkVersion", "targetSdkVersion", "name"}
REVIEW = {
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
}
NONE = 0xFFFFFFFF


def _vl8(data: bytes, at: int) -> tuple[int, int]:
    first = data[at]
    return (((first & 0x7F) << 8) | data[at + 1], at + 2) if first & 0x80 else (first, at + 1)


def _pool(data: bytes, start: int, size: int, header: int) -> list[str]:
    count, _, flags, base, _ = struct.unpack_from("<IIIII", data, start + 8)
    if header < 28 or base < header + count * 4 or count > 12000 or base > size:
        raise ValueError("pool")
    out = []
    for idx in range(count):
        offset = struct.unpack_from("<I", data, start + header + idx * 4)[0]
        position = start + base + offset
        if position >= start + size:
            raise ValueError("string")
        if flags & 0x100:
            _, pos = _vl8(data, position)
            length, pos = _vl8(data, pos)
            encoding = "utf-8"
        else:
            length = struct.unpack_from("<H", data, position)[0]
            pos = position + 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                pos += 2
            length *= 2
            encoding = "utf-16-le"
        if pos + length >= start + size:
            raise ValueError("length")
        out.append(data[pos : pos + length].decode(encoding))
    return out


def _binary_manifest(data: bytes) -> list[tuple[str, dict]]:
    kind, header, length = struct.unpack_from("<HHI", data)
    if kind != 3 or not 8 <= header <= length <= len(data):
        raise ValueError("root")
    cursor = header
    strings: list[str] = []
    entries = []
    while cursor < length:
        kind, header, size = struct.unpack_from("<HHI", data, cursor)
        if not 8 <= header <= size or cursor + size > length:
            raise ValueError("chunk")
        if kind == 1:
            strings = _pool(data, cursor, size, header)
        if kind == 0x0102:
            if header < 16 or header + 20 > size:
                raise ValueError("node")
            start = cursor + header
            _, tag, attr_offset, attr_size, count = struct.unpack_from("<IIHHH", data, start)
            if (
                not strings
                or attr_size < 20
                or attr_offset < 20
                or count > 1000
                or start + attr_offset + attr_size * count > cursor + size
            ):
                raise ValueError("attributes")
            element = strings[tag]
            if element in {"manifest", "uses-sdk", "uses-permission", "uses-permission-sdk-23"}:
                attrs = {}
                for i in range(count):
                    pos = start + attr_offset + i * attr_size
                    _, name, raw, _, _, data_type, value = struct.unpack_from("<IIIHBBI", data, pos)
                    key = strings[name]
                    if key in WANTED:
                        if raw != NONE:
                            attrs[key] = strings[raw]
                        elif data_type == 3:
                            attrs[key] = strings[value]
                        elif data_type in (0x10, 0x11):
                            attrs[key] = str(value)
                entries.append((element, attrs))
        cursor += size
    return entries


def parse_manifest(data: bytes) -> dict:
    if len(data) > MAX_MEMBER or not data:
        raise InspectorError("Ukuran manifest APK tidak didukung.")
    try:
        if data.lstrip().startswith(b"<"):
            if b"\0" in data or re.search(rb"<!\s*(DOCTYPE|ENTITY)\b", data, re.I):
                raise ValueError("XML")
            root = ElementTree.fromstring(data)
            entries = [
                (node.tag, {key.removeprefix(ANDROID): val for key, val in node.attrib.items()})
                for node in root.iter()
            ]
        else:
            entries = _binary_manifest(data)
        if not entries or entries[0][0] != "manifest":
            raise ValueError("manifest")
        first = entries[0][1]
        package = first.get("package", "")
        if (
            not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package, flags=re.ASCII)
            or len(package) > 255
        ):
            raise ValueError("package")
        sdk = next((attrs for tag, attrs in entries if tag == "uses-sdk"), {})
        permissions = sorted(
            {
                attrs["name"][:160]
                for tag, attrs in entries
                if tag in ("uses-permission", "uses-permission-sdk-23") and attrs.get("name")
            }
        )[:200]
    except (IndexError, UnicodeError, ValueError, struct.error, ElementTree.ParseError) as error:
        raise InspectorError("Manifest APK rusak atau memakai format tidak didukung.") from error
    return {
        "package": package,
        "version_name": first.get("versionName", "")[:120],
        "version_code": first.get("versionCode"),
        "min_sdk": sdk.get("minSdkVersion"),
        "target_sdk": sdk.get("targetSdkVersion"),
        "permissions": permissions,
        "permissions_for_review": sorted(REVIEW.intersection(permissions)),
    }


def _member(archive, info):
    if info.file_size > MAX_MEMBER or info.flag_bits & 1:
        raise InspectorError("Entri APK terlalu besar atau terenkripsi.")
    with archive.open(info) as handle:
        data = handle.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER:
        raise InspectorError("Entri APK melampaui batas baca.")
    return data


def inspect_apk(path: Path, cancel: Event) -> Observation:
    if path.suffix.lower() != ".apk":
        raise InspectorError("Pilih berkas dengan ekstensi .apk.")
    with open_selected(path) as (handle, info):
        computed = hashes(handle, info.st_size, cancel, lambda *_: None)
        check_cancel(cancel)
        with bounded_zip(handle, info.st_size) as archive:
            manifests = [entry for entry in archive.infolist() if entry.filename == "AndroidManifest.xml"]
            if len(manifests) != 1:
                raise InspectorError("APK harus berisi tepat satu AndroidManifest.xml.")
            payload = parse_manifest(_member(archive, manifests[0]))
            certificates = []
            for entry in archive.infolist():
                check_cancel(cancel)
                if len(certificates) >= 12:
                    break
                if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", entry.filename, re.I):
                    try:
                        from cryptography.hazmat.primitives import hashes as crypto_hashes

                        for cert in pkcs7.load_der_pkcs7_certificates(_member(archive, entry))[:4]:
                            certificates.append(
                                {
                                    "certificate_sha256": cert.fingerprint(crypto_hashes.SHA256()).hex(),
                                    "not_valid_after": cert.not_valid_after_utc.isoformat(),
                                }
                            )
                    except (ValueError, InspectorError):
                        continue
            payload.update(
                filename=path.name[:240],
                sha256=computed["sha256"],
                certificates=certificates[:12],
                signature_notice="Sertifikat JAR/v1 jika tersedia. Signature APK, trust, dan skema v2/v3 belum diverifikasi.",
            )
    findings = (
        (
            Finding(
                "apk_permissions_review",
                "Deklarasi izin APK memerlukan peninjauan",
                "informational",
                "Tinjau alasan teknis dan kebijakan institusi untuk izin yang dideklarasikan.",
            ),
        )
        if payload["permissions_for_review"]
        else ()
    )
    return Observation("AndroidManifest.xml dan metadata sertifikat JAR", payload, findings)
