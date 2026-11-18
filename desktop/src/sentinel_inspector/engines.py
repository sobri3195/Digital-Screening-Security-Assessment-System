from hashlib import sha256
from pathlib import Path
import platform
import re
import shutil
from threading import Event
from time import monotonic
from uuid import uuid4

from .database import Database, InspectorError, now
from .file_inspection import Cancelled, check_cancel, open_selected, path_stat
from .models import Finding, Observation
from .platforms import Unavailable, command, powershell, windows_directory

MAX_RULE = 64 * 1024
MAX_ENGINE_FILE = 64 * 1024 * 1024


def compile_rules(text: str):
    try:
        import yara
    except ImportError as error:
        raise Unavailable("YARA belum terpasang.") from error
    try:
        return yara.compile(source=text, includes=False, error_on_warning=True)
    except yara.Error as error:
        raise InspectorError(
            "Aturan YARA tidak valid atau mengandung include/konfigurasi yang tidak didukung."
        ) from error


def register_rule(db: Database, path: Path, label: str, version: str) -> str:
    if not label.strip() or not version.strip() or len(label) > 120 or len(version) > 40:
        raise InspectorError("Isi nama dan versi aturan.")
    with open_selected(path, MAX_RULE) as (handle, _):
        data = handle.read(MAX_RULE + 1)
    if not data or len(data) > MAX_RULE:
        raise InspectorError("Aturan YARA kosong atau melebihi 64 KiB.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as error:
        raise InspectorError("Aturan YARA harus berupa UTF-8.") from error
    compile_rules(text)
    code = uuid4().hex
    with db.write() as c:
        row = c.exec_driver_sql(
            "INSERT OR IGNORE INTO yara_rules VALUES (?,?,?,?,?,0,?)",
            (code, label.strip(), version.strip(), sha256(data).hexdigest(), text, now()),
        )
        if row.rowcount != 1:
            raise InspectorError("Aturan atau versi sudah terdaftar.")
        db.audit(c, None, "yara_imported", {"rule_id": code})
    return code


def toggle_rule(db: Database, code: str, active: bool):
    with db.write() as c:
        if active:
            total = c.exec_driver_sql(
                "SELECT COUNT(*) FROM yara_rules WHERE enabled=1 AND id<>?", (code,)
            ).scalar_one()
            if total >= 5:
                raise InspectorError("Maksimum lima kumpulan aturan aktif.")
        updated = c.exec_driver_sql("UPDATE yara_rules SET enabled=? WHERE id=?", (int(active), code))
        if updated.rowcount != 1:
            raise InspectorError("Aturan tidak ditemukan.")
        db.audit(c, None, "yara_status_changed", {"rule_id": code, "enabled": active})


def yara_scan(db: Database, path: Path, cancel: Event) -> dict:
    rules = db.rows(
        "SELECT label,version,sha256,rules FROM yara_rules WHERE enabled=1 ORDER BY created_at LIMIT 5"
    )
    if not rules:
        return {
            "engine": "YARA",
            "status": "unavailable",
            "notice": "Tidak ada aturan yang ditinjau dan diaktifkan.",
        }
    try:
        import yara
    except ImportError:
        return {"engine": "YARA", "status": "unavailable", "notice": "Engine belum terpasang."}
    with open_selected(path, MAX_ENGINE_FILE) as (handle, _):
        data = bytearray()
        while block := handle.read(1024 * 1024):
            check_cancel(cancel)
            data.extend(block)
            if len(data) > MAX_ENGINE_FILE:
                raise InspectorError("File melebihi batas YARA.")
    raw = bytes(data)
    matches = []
    failures = 0
    started = monotonic()
    for entry in rules:
        check_cancel(cancel)
        try:
            compiled = compile_rules(entry["rules"])
            for match in compiled.match(data=raw, timeout=4):
                matches.append(
                    {
                        "rule": match.rule,
                        "ruleset": entry["label"],
                        "ruleset_version": entry["version"],
                        "ruleset_sha256": entry["sha256"],
                    }
                )
                if len(matches) >= 100:
                    break
            if len(matches) >= 100:
                break
        except (yara.Error, InspectorError):
            failures += 1
    check_cancel(cancel)
    return {
        "engine": "YARA",
        "version": getattr(yara, "__version__", None),
        "status": "review" if matches else ("incomplete" if failures else "no_indicators"),
        "sha256": sha256(raw).hexdigest(),
        "matches": matches,
        "failed_rulesets": failures,
        "duration_ms": round((monotonic() - started) * 1000),
        "matched_at": now(),
    }


def clam_scan(path: Path, cancel: Event) -> dict:
    binary = shutil.which("clamscan")
    if not binary:
        return {"engine": "ClamAV", "status": "unavailable", "notice": "clamscan tidak tersedia."}
    try:
        code, version = command([binary, "--version"], cancel, 10)
        version_text = (
            version.decode("utf-8", errors="replace").splitlines()[0][:150] if version and not code else None
        )
        status, report = command(
            [
                binary,
                "--stdout",
                "--no-summary",
                "--max-files=1000",
                "--max-recursion=8",
                "--max-filesize=64M",
                "--max-scansize=128M",
                "--alert-exceeds-max=yes",
                str(path),
            ],
            cancel,
            65,
        )
    except Cancelled:
        raise
    except InspectorError:
        return {
            "engine": "ClamAV",
            "status": "incomplete",
            "notice": "Proses tidak selesai atau batas waktu terlampaui.",
        }
    match = re.search(rb": ([A-Za-z0-9_.-]{1,150}) FOUND\r?$", report, re.MULTILINE) if status == 1 else None
    name = match[1].decode("ascii") if match else None
    result = (
        "detected"
        if name and not name.startswith("Heuristics.Limits.Exceeded")
        else ("review" if status == 1 else ("no_indicators" if status == 0 else "incomplete"))
    )
    return {
        "engine": "ClamAV",
        "version_and_signature": version_text,
        "status": result,
        "detection": name,
        "exit_code": status,
        "scanned_at": now(),
    }


def _defender_path() -> Path | None:
    if platform.system() != "Windows":
        return None
    windows = windows_directory()
    system = Path(windows.anchor)
    platform_dir = system / "ProgramData" / "Microsoft" / "Windows Defender" / "Platform"
    try:

        def version_key(path):
            return tuple(int(part) for part in re.findall(r"\d+", path.name))

        candidates = sorted(
            platform_dir.glob("*/MpCmdRun.exe"), key=lambda path: version_key(path.parent), reverse=True
        )
    except OSError:
        candidates = []
    candidates.append(system / "Program Files" / "Windows Defender" / "MpCmdRun.exe")
    return next((path for path in candidates if path.is_file()), None)


DEFENDER_OFFLINE_POLICY = r"""
$ErrorActionPreference='Stop'
$p=Get-MpPreference
@{ cloud=[int]$p.MAPSReporting; sample=[int]$p.SubmitSamplesConsent } | ConvertTo-Json -Compress
"""


def defender_scan(path: Path, cancel: Event) -> dict:
    binary = _defender_path()
    if binary is None:
        return {
            "engine": "Microsoft Defender",
            "status": "unavailable",
            "notice": "Antarmuka Defender lokal tidak tersedia.",
        }
    try:
        preferences = powershell(DEFENDER_OFFLINE_POLICY, cancel)
        if (
            not isinstance(preferences, dict)
            or preferences.get("cloud") != 0
            or preferences.get("sample") != 2
        ):
            return {
                "engine": "Microsoft Defender",
                "status": "unavailable",
                "notice": "Kebijakan cloud/submisi sampel tidak dikonfirmasi nonaktif; pemeriksaan lokal dilewati.",
            }
        status, _ = command(
            [str(binary), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"], cancel, 75
        )
    except Cancelled:
        raise
    except InspectorError:
        return {
            "engine": "Microsoft Defender",
            "status": "incomplete",
            "notice": "Proses tidak selesai atau aksesnya ditolak.",
        }
    return {
        "engine": "Microsoft Defender",
        "version": binary.parent.name if binary.parent.name[0].isdigit() else None,
        "status": "no_indicators" if status == 0 else ("review" if status == 2 else "incomplete"),
        "exit_code": status,
        "scanned_at": now(),
        "notice": "Mode pemeriksaan satu file dengan remediasi dinonaktifkan. Kode 2 perlu verifikasi.",
    }


def scan(db: Database, path: Path, cancel: Event, engines: set[str]) -> Observation:
    original = path_stat(path)
    if original.st_size > MAX_ENGINE_FILE:
        raise InspectorError("Engine malware dibatasi pada file pilihan hingga 64 MiB.")
    results = []
    for name, process in (
        ("yara", lambda: yara_scan(db, path, cancel)),
        ("clamav", lambda: clam_scan(path, cancel)),
        ("defender", lambda: defender_scan(path, cancel)),
    ):
        if name in engines:
            check_cancel(cancel)
            results.append(process())
    current = path_stat(path)
    if not (
        original.st_size == current.st_size
        and original.st_mtime_ns == current.st_mtime_ns
        and original.st_dev == current.st_dev
        and original.st_ino == current.st_ino
    ):
        raise InspectorError("File berubah selama pemeriksaan; hasil engine diabaikan.")
    findings = []
    for result in results:
        if result["status"] in ("detected", "review"):
            findings.append(
                Finding(
                    "malware_indicator",
                    f"Hasil {result['engine']} memerlukan tinjauan",
                    "high" if result["status"] == "detected" else "medium",
                    "Validasi hasil engine dan eskalasi melalui petugas keamanan informasi. Jangan jalankan file.",
                )
            )
    return Observation(
        "Engine yang dipilih operator", {"filename": path.name[:240], "engines": results}, tuple(findings)
    )
