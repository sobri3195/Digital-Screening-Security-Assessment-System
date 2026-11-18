import csv
from hashlib import sha256
from io import BytesIO, StringIO
import json
from pathlib import Path
import re
from textwrap import wrap
from uuid import uuid4

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from .backup import exclusive
from .database import Database, InspectorError, now
from .posture import evaluate

KINDS = {
    "complete": ("Penilaian Keamanan Perangkat", None),
    "windows": ("Penilaian Keamanan Windows", {"windows", "software"}),
    "android": ("Checklist Keamanan Android", {"android"}),
    "ios": ("Checklist Keamanan iOS", {"ios"}),
    "usb": ("Koneksi Perangkat USB", {"usb"}),
    "malware": ("Analisis Malware", {"malware"}),
    "apk": ("Analisis Keamanan APK", {"apk"}),
    "integrity": ("Integritas File", {"files"}),
    "vulnerability": ("Penilaian Kerentanan", {"vulnerability"}),
    "intel": ("Intelijen Ancaman", {"intelligence", "files"}),
    "mitigation": ("Mitigasi Keamanan", None),
}


def document(db: Database, session: str, kind: str) -> dict:
    if kind not in KINDS:
        raise InspectorError("Jenis laporan tidak valid.")
    record = db.session(session)
    if record["status"] in ("ready", "running", "cancelled"):
        raise InspectorError("Laporan tersedia setelah sesi siap ditinjau.")
    rule = db.score_rule(record["scoring_rule"])
    posture = evaluate(record, rule)
    title, modules = KINDS[kind]
    evidence = [row for row in record["evidence"] if modules is None or row["module"] in modules]
    if kind == "usb":
        evidence = [
            {"source": "Monitor USB lokal", "payload": row, "verified_integrity": None, "sha256": "—"}
            for row in db.rows(
                """SELECT event,category,manufacturer,model,driver_status,observed_at FROM usb_events
                WHERE observed_at>=? AND observed_at<=? ORDER BY observed_at LIMIT 200""",
                (record["started_at"], record["ended_at"]),
            )
        ]
    evidence_ids = {row.get("id") for row in evidence}
    finds = [row for row in record["findings"] if row["evidence_id"] in evidence_ids]
    return {
        "document": "PSI-" + session[:10].upper() + "-" + kind.upper(),
        "title": title,
        "institution": "Pusat Kesehatan TNI Angkatan Udara",
        "generated_at": now(),
        "kind": kind,
        "session": {
            key: value
            for key, value in record.items()
            if key not in {"evidence", "findings", "tasks", "timeline"}
        },
        "method": "Pemeriksaan konfigurasi teknis dan analisis statis lokal sesuai modul yang disetujui.",
        "tasks": [row for row in record["tasks"] if modules is None or row["module"] in modules],
        "posture": posture,
        "findings": finds,
        "evidence": evidence,
        "timeline": record["timeline"],
        "limitations": "Status tidak tersedia, cakupan parsial, dan katalog yang tidak lengkap menuntut verifikasi tambahan. Laporan ini bersifat internal.",
    }


def preview(data: dict) -> str:
    record = data["session"]
    assessment = data["posture"]
    lines = [
        data["institution"],
        "DOKUMEN INTERNAL",
        data["title"],
        f"No. {data['document']}",
        f"Dibuat {data['generated_at']}",
        "",
        f"Aset: {record['asset_code']} · {record['asset_name']} ({record['platform']})",
        f"Otorisasi: {record['reference']} · Petugas: {record['operator_code']}",
        f"Peninjau: {record.get('reviewer_code') or 'Menunggu peninjauan'}",
        f"Ruang lingkup: {record['scope']}",
        f"Metodologi: {data['method']}",
        f"Posture: {assessment['category']}, skor {assessment['score'] if assessment['score'] is not None else '—'}, cakupan {assessment['coverage']}%",
        f"Keterbatasan: {data['limitations']}",
        "",
        f"Temuan dalam laporan: {len(data['findings'])}",
    ]
    for task in data["tasks"]:
        lines.append(f"- {task['module']}: {task['status']} · {task['notice']}")
    for finding in data["findings"]:
        lines += [
            f"- {finding['severity']}: {finding['title']} ({finding['status']})",
            f"  Rekomendasi: {finding['recommendation']}",
        ]
    lines += ["", "Bukti teknis"]
    for item in data["evidence"]:
        text = json.dumps(item["payload"], ensure_ascii=False, separators=(",", ":"))
        lines += [
            f"- {item['source']} · SHA-256 {item['sha256']}",
            text if len(text) <= 5000 else text[:5000] + " … [lihat JSON]",
        ]
    timeline = data["timeline"]
    lines += ["", "Linimasa", *(f"- {row['occurred_at']} · {row['event']}" for row in timeline)]
    return "\n".join(lines)


def _pdf(data: dict) -> bytes:
    memory = BytesIO()
    pdf = canvas.Canvas(memory, pagesize=A4, pageCompression=1)
    pdf.setTitle(data["title"])
    pdf.setAuthor(data["institution"])
    width, height = A4
    page = 0
    y = 0

    def start_page():
        nonlocal page, y
        page += 1
        pdf.setFillColor(HexColor("#122137"))
        pdf.rect(0, height - 58, width, 58, fill=True, stroke=False)
        pdf.setFillColor(HexColor("#F8FAFC"))
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(36, height - 35, "PUSKESAU SENTINEL  /  DOKUMEN INTERNAL")
        pdf.setFillColor(HexColor("#33435E"))
        pdf.setFont("Helvetica", 9)
        pdf.drawString(36, 25, data["document"])
        pdf.drawRightString(width - 36, 25, f"Halaman {page}")
        y = height - 78

    start_page()
    for raw in preview(data).splitlines():
        for line in wrap(raw, 100, replace_whitespace=False) or [""]:
            if y < 49:
                pdf.showPage()
                start_page()
            pdf.drawString(36, y, line)
            y -= 12
    pdf.save()
    return memory.getvalue()


def _csv(data: dict) -> bytes:
    result = StringIO(newline="")
    writer = csv.writer(result)
    writer.writerow(("report", "asset", "section", "item", "status", "detail"))

    def row(section, item, status, text):
        values = (data["document"], data["session"]["asset_code"], section, item, status, text)
        writer.writerow(
            [
                "'" + value
                if isinstance(value, str)
                and (re.match(r"^\s*[=+@-]", value) or value.startswith(("\r", "\n", "\t")))
                else value
                for value in values
            ]
        )

    for task in data["tasks"]:
        row("task", task["module"], task["status"], task["notice"])
    for finding in data["findings"]:
        row("finding", finding["title"], finding["status"], finding["recommendation"])
    for evidence in data["evidence"]:
        row(
            "evidence",
            evidence["source"],
            evidence["sha256"],
            json.dumps(evidence["payload"], ensure_ascii=False),
        )
    return result.getvalue().encode("utf-8-sig")


def export(db: Database, session: str, kind: str, out: Path) -> str:
    result = document(db, session, kind)
    extension = out.suffix.lower().removeprefix(".")
    if extension == "pdf":
        content = _pdf(result)
    elif extension == "csv":
        content = _csv(result)
    elif extension == "json":
        content = json.dumps(result, ensure_ascii=False, indent=2).encode()
    else:
        raise InspectorError("Gunakan ekstensi PDF, JSON atau CSV.")
    exclusive(out, content)
    checksum = sha256(content).hexdigest()
    with db.write() as c:
        c.exec_driver_sql(
            "INSERT INTO reports VALUES (?,?,?,?,?,?)",
            (uuid4().hex, session, kind, extension, checksum, now()),
        )
        db.audit(c, session, "report_generated", {"kind": kind, "format": extension, "sha256": checksum})
    return checksum
