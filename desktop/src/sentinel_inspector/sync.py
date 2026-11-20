from getpass import getpass
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

import httpx

from . import reporting
from .database import Database, InspectorError, digest


def summary(db: Database, session: str, revision: int | None) -> dict:
    report = reporting.document(db, session, "complete", revision)
    if report["revision"] is None:
        raise InspectorError("Hanya revisi laporan final yang dapat dikirim.")
    return {
        "schema": "sentinel-inspection-v1", "asset_code": report["session"]["asset_code"],
        "session_id": session, "revision": report["revision"], "report_sha256": digest(report),
        "score": report["posture"]["score"], "coverage": report["posture"]["coverage"],
        "finding_count": len(report["findings"]), "tasks_total": len(report["tasks"]),
        "tasks_completed": sum(task["status"] == "complete" for task in report["tasks"]),
    }


def send(payload: dict, origin: str, client_id: int, ca: Path | None) -> dict:
    address = urlsplit(origin)
    if (
        address.scheme != "https" or not address.hostname or address.username is not None or address.password is not None
        or address.port == 0 or address.path not in ("", "/") or address.query or address.fragment or client_id < 1
    ):
        raise InspectorError("Gunakan origin HTTPS unit dan ID klien yang valid.")
    secret = getpass("Rahasia klien API unit: ")
    if not re.fullmatch(r"[a-f0-9]{64}", secret):
        raise InspectorError("Format rahasia klien API tidak valid.")
    try:
        trusted = ssl.create_default_context(cafile=str(ca)) if ca else True
        with httpx.Client(base_url=f"https://{address.netloc}", timeout=8, verify=trusted,
                          follow_redirects=False, trust_env=False) as client:
            response = client.post("/api/v1/auth/token", json={"client_id": client_id, "client_secret": secret})
            if response.status_code != 200:
                raise InspectorError(f"Penerbitan token ditolak (HTTP {response.status_code}).")
            token = response.json().get("access_token")
            if not isinstance(token, str) or not re.fullmatch(r"[a-f0-9]{64}", token):
                raise InspectorError("Respons token tidak valid.")
            response = client.post(
                "/api/v1/threat-intelligence/desktop-results",
                headers={"Authorization": "Bearer " + token}, json=payload,
            )
            if response.status_code not in (200, 201):
                raise InspectorError(f"Ringkasan Desktop ditolak (HTTP {response.status_code}).")
            result = response.json().get("data")
            if not isinstance(result, dict) or result.get("state") not in ("received", "already_received"):
                raise InspectorError("Respons penerimaan tidak valid.")
            return result
    except (httpx.HTTPError, OSError, ValueError, AttributeError):
        raise InspectorError("Koneksi HTTPS unit atau respons API tidak valid.") from None
