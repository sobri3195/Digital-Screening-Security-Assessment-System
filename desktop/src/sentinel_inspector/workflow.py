from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Callable

from . import apk, engines, file_inspection, intelligence, platforms
from .database import Database, InspectorError
from .file_inspection import Cancelled, check_cancel
from .models import FILE_MODULES, MobileCheck, Module, Observation, Product

MAX_FILES = 12
MAX_INDICATORS = 20


@dataclass
class Selection:
    modules: set[Module]
    files: tuple[Path, ...] = ()
    mobile_checks: tuple[MobileCheck, ...] = ()
    indicators: tuple[str, ...] = ()
    products: tuple[Product, ...] = ()
    engines: set[str] = field(default_factory=set)


def run(
    db: Database,
    session: str,
    selection: Selection,
    cancel: Event,
    progress: Callable[[str, int, int, str], None] = lambda *_: None,
):
    if selection.files and not selection.modules & FILE_MODULES:
        raise InspectorError("File hanya dapat dipilih untuk modul yang diotorisasi.")
    if len(selection.files) > MAX_FILES or len(set(selection.files)) != len(selection.files):
        raise InspectorError("Pilih paling banyak 12 file unik secara manual.")
    if (
        len(selection.indicators) > MAX_INDICATORS
        or len(selection.products) > 500
        or not selection.engines <= {"defender", "clamav", "yara"}
    ):
        raise InspectorError("Pilihan pemeriksaan melampaui batas.")
    if Module.MALWARE in selection.modules and not selection.engines:
        raise InspectorError("Pilih setidaknya satu engine malware atau gunakan modul file dan lookup hash.")
    db.start(session, selection.modules)
    total = len(selection.modules)
    ordered = [module for module in Module if module in selection.modules]
    cached_products = list(selection.products)
    try:
        for count, module in enumerate(ordered, start=1):
            check_cancel(cancel)
            db.running(session, module)
            progress(module.value, count - 1, total, "Modul berjalan.")
            observed = []
            status, notice = "complete", "Selesai."
            try:
                if module == Module.WINDOWS:
                    observed.append(platforms.security(cancel))
                elif module == Module.SOFTWARE:
                    inventory = platforms.software(cancel)
                    observed.append(inventory)
                    cached_products += [
                        Product(vendor=entry["vendor"], name=entry["name"], version=entry["version"])
                        for entry in inventory.payload["products"]
                        if entry["vendor"].strip() and entry["name"].strip() and entry["version"].strip()
                    ]
                elif module in (Module.ANDROID, Module.IOS):
                    observed.append(platforms.mobile(module.value, selection.mobile_checks))
                elif module in FILE_MODULES:
                    observed, status, notice = _files(
                        db, module, selection, cancel, progress, count - 1, total
                    )
                elif module == Module.VULNERABILITY:
                    if not cached_products:
                        raise platforms.Unavailable(
                            "Masukkan versi produk terverifikasi atau jalankan inventaris lokal."
                        )
                    observed.append(intelligence.assess(db, cached_products))
                elif module == Module.INTELLIGENCE:
                    if not selection.indicators:
                        raise platforms.Unavailable("Belum ada indikator yang dipilih.")
                    for item in selection.indicators:
                        check_cancel(cancel)
                        observed.append(intelligence.lookup(db, item))
            except Cancelled:
                raise
            except platforms.Unavailable as error:
                status, notice = "unavailable", str(error)
            except InspectorError as error:
                status, notice = "failed", str(error)
            except (OSError, ValueError, TypeError, KeyError, OverflowError):
                status, notice = "failed", "Modul tidak dapat menyelesaikan validasi data."
            check_cancel(cancel)
            db.finish_task(session, module, status, notice, observed)
            progress(module.value, count, total, notice)
    except Cancelled:
        db.finish(session, True)
        return
    except Exception:
        db.finish(session, True)
        raise
    db.finish(session, False)


def _files(db, module, selection, cancel, progress, index, total):
    paths = [path for path in selection.files if module != Module.APK or path.suffix.lower() == ".apk"]
    if not paths:
        return [], "unavailable", "Tidak ada file yang dipilih untuk modul."
    observed, failures, unavailable = [], 0, 0
    for number, path in enumerate(paths, start=1):
        check_cancel(cancel)
        try:
            if module == Module.APK:
                result = apk.inspect_apk(path, cancel)
                observed.append(intelligence.lookup(db, result.payload["sha256"]))
            elif module == Module.MALWARE:
                result = engines.scan(db, path, cancel, selection.engines)
                outcomes = [item["status"] for item in result.payload["engines"]]
                if outcomes and all(status == "unavailable" for status in outcomes):
                    unavailable += 1
                elif "incomplete" in outcomes:
                    failures += 1
            else:
                notify_bytes = 0

                def notify(read, size):
                    nonlocal notify_bytes
                    if read == size or read - notify_bytes >= 16 * 1024 * 1024:
                        notify_bytes = read
                        progress(
                            module.value,
                            index,
                            total,
                            f"File {number}/{len(paths)}: {read:,} / {size:,} byte dibaca.",
                        )

                metadata = file_inspection.inspect(path, cancel, notify)
                observed.append(metadata.observation())
                result = intelligence.lookup(db, metadata.hashes["sha256"])
            observed.append(result)
        except Cancelled:
            raise
        except (InspectorError, OSError, ValueError) as error:
            failures += 1
            message = str(error) if isinstance(error, InspectorError) else "Isi file tidak dapat diproses."
            observed.append(
                Observation("Validasi file lokal", {"filename": path.name[:240], "error": message})
            )
    status = "failed" if failures else ("unavailable" if unavailable else "complete")
    return (
        observed,
        status,
        f"{len(paths) - failures - unavailable}/{len(paths)} file selesai. Engine tidak tersedia: {unavailable}.",
    )


def api_health(url: str) -> dict:
    """Explicit check of the configured service. No inspection data is sent."""
    from urllib.parse import urlsplit
    import httpx

    try:
        endpoint = urlsplit(url.strip())
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.port == 0
            or endpoint.path not in ("", "/")
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError
        target = f"https://{endpoint.netloc}/api/v1/health"
        with httpx.Client(timeout=5, follow_redirects=False) as client:
            with client.stream("GET", target, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    return {"status": "tidak_tersedia", "http_status": response.status_code}
                raw = bytearray()
                for chunk in response.iter_bytes(chunk_size=1024):
                    raw.extend(chunk)
                    if len(raw) > 8192:
                        return {"status": "respons_tidak_valid"}
                import json

                data = json.loads(bytes(raw))
                if not isinstance(data, dict) or data.get("status") != "ok":
                    return {"status": "respons_tidak_valid"}
                return {"status": "ok", "version": str(data.get("version", ""))[:60]}
    except (ValueError, httpx.HTTPError):
        return {
            "status": "tidak_tersedia",
            "notice": "Gunakan origin HTTPS resmi institusi dengan sertifikat tepercaya.",
        }
