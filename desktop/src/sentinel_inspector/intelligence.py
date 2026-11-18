from base64 import b64decode
from datetime import UTC, datetime
from hashlib import sha256
import hmac
from ipaddress import ip_address
import json
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

import idna

from .database import Database, InspectorError, json_text, now
from .models import Finding, Observation, Product

MAX_PACKAGE = 4 * 1024 * 1024
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z", re.ASCII)
HEX = re.compile(r"[a-f0-9]+\Z", re.ASCII)
NUM_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,12}\Z", re.ASCII)


def _domain(host: str) -> str:
    try:
        encoded = idna.encode(host.rstrip("."), uts46=True, std3_rules=True).decode("ascii")
        if "." not in encoded or re.fullmatch(r"[0-9.]+", encoded):
            raise ValueError
        return encoded
    except (ValueError, idna.IDNAError) as error:
        raise InspectorError("Hostname DNS tidak valid.") from error


def _address(value: str):
    if "%" in value:
        raise ValueError("zone")
    address = ip_address(value)
    canonical = (
        f"::ffff:{address.ipv4_mapped}" if getattr(address, "ipv4_mapped", None) else address.compressed
    )
    return f"ipv{address.version}", canonical


def refang(value: str) -> str:
    if value.startswith(("hxxp://", "hxxps://")):
        return "http" + value[4:].replace("[.]", ".")
    if "[:]" in value and "/" not in value:
        return value.replace("[:]", ":")
    if "[.]" in value and "/" not in value:
        return value.replace("[.]", ".")
    return value


def indicator(raw: str) -> tuple[str, str, str, str | None]:
    if not isinstance(raw, str):
        raise InspectorError("Indikator harus berupa teks.")
    value = refang(raw.strip())
    if (
        len(value.encode("utf-8", errors="replace")) > 2048
        or re.search(r"[\x00-\x20\x7f\\]", value)
        or not value
    ):
        raise InspectorError("Masukkan domain, IP, hash, URL, atau CVE yang valid.")
    host = None
    if CVE.fullmatch(value.upper()):
        kind = "cve"
        canonical = shown = value.upper()
    elif len(value) in (32, 40, 64) and HEX.fullmatch(value.lower()):
        kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
        canonical = shown = value.lower()
    else:
        try:
            kind, canonical = _address(value)
            shown = canonical.replace(":", "[:]") if kind == "ipv6" else canonical.replace(".", "[.]")
        except ValueError:
            if not value.lower().startswith(("http://", "https://")):
                host = _domain(value)
                kind = "domain"
                canonical = host
                shown = host.replace(".", "[.]")
            else:
                try:
                    parts = urlsplit(value)
                    if (
                        not parts.hostname
                        or parts.username is not None
                        or parts.password is not None
                        or parts.port == 0
                    ):
                        raise ValueError
                    try:
                        _, host = _address(parts.hostname)
                    except ValueError:
                        host = _domain(parts.hostname)
                    authority = "[" + host + "]" if ":" in host else host
                    if parts.port and parts.port != (443 if parts.scheme == "https" else 80):
                        authority += f":{parts.port}"
                    canonical = f"{parts.scheme}://{authority}{parts.path or '/'}"
                    shown = ("hxxp" + canonical[4:]).replace(".", "[.]")
                    if "?" in value.split("#", 1)[0]:
                        canonical += "?" + parts.query
                    kind = "url"
                except ValueError as error:
                    raise InspectorError("URL harus memakai HTTP/HTTPS tanpa kredensial.") from error
    return kind, sha256(canonical.encode()).hexdigest(), shown, host


def checked_package(data: bytes) -> tuple[str, list, list, list, str | None, str]:
    if not data or len(data) > MAX_PACKAGE:
        raise InspectorError("Paket kosong atau melebihi 4 MiB.")
    try:
        outer = json.loads(data)
        if not isinstance(outer, dict) or outer.get("format") not in (
            "sentinel-ioc-v1",
            "sentinel-endpoint-v1",
        ):
            raise ValueError
        encoded = outer.get("payload")
        expected = outer.get("sha256")
        if (
            not isinstance(encoded, str)
            or not isinstance(expected, str)
            or not hmac.compare_digest(sha256(encoded.encode("ascii")).hexdigest(), expected)
        ):
            raise ValueError
        inner = json.loads(b64decode(encoded, validate=True))
        if outer["format"] == "sentinel-ioc-v1":
            categories = (inner, [], [])
            source_updated = None
        elif isinstance(inner, dict):
            categories = tuple(inner.get(key, []) for key in ("indicators", "vulnerabilities", "advisories"))
            source_updated = stamp(inner.get("source_updated_at"))
        else:
            raise ValueError
        if any(
            not isinstance(rows, list) or len(rows) > 2000 or any(not isinstance(row, dict) for row in rows)
            for rows in categories
        ):
            raise ValueError
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise InspectorError("Format atau checksum paket tidak valid.") from error
    return outer["format"], *categories, source_updated, expected


def string(value, limit=160) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def stamp(value):
    if not isinstance(value, str):
        return None
    try:
        observed = datetime.fromisoformat(value)
        if observed.tzinfo is None:
            return None
        return observed.astimezone(UTC).isoformat(timespec="milliseconds")
    except (ValueError, OverflowError):
        return None


def fraction(value, high):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    return number if math.isfinite(number) and 0 <= number <= high else None


def load_package(db: Database, path: Path) -> dict:
    from .file_inspection import open_selected

    with open_selected(path, MAX_PACKAGE) as (handle, _):
        document = handle.read(MAX_PACKAGE + 1)
    format_name, iocs, cves, advisories, source_updated, checksum = checked_package(document)
    with db.write() as c:
        receipt = c.exec_driver_sql(
            """INSERT INTO intelligence_imports (source,checksum,imported_at,source_updated_at) VALUES (?,?,?,?)
            ON CONFLICT(checksum) DO NOTHING""",
            (format_name, checksum, now(), source_updated),
        )
        if not receipt.rowcount:
            return {"already_imported": True}
        import_id = receipt.lastrowid
        for row in iocs:
            kind, fingerprint, value, _ = indicator(row.get("value"))
            if kind == "cve":
                raise InspectorError("Gunakan rekaman kerentanan untuk CVE.")
            source = string(row.get("origin_provider"), 60) or "paket offline"
            reference = string(row.get("reference"), 500)
            if reference:
                try:
                    reference = indicator(reference)[2]
                except InspectorError:
                    reference = None
            confidence = fraction(row.get("confidence"), 100)
            c.exec_driver_sql(
                """INSERT INTO indicators VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(kind,fingerprint,source) DO UPDATE SET
                    category=excluded.category,severity=excluded.severity,confidence=excluded.confidence,
                    first_seen=COALESCE(excluded.first_seen,indicators.first_seen),last_seen=COALESCE(excluded.last_seen,indicators.last_seen),
                    expires_at=excluded.expires_at,family=excluded.family,reference=excluded.reference,import_id=excluded.import_id""",
                (
                    kind,
                    fingerprint,
                    value,
                    source,
                    string(row.get("category"), 40) or "unknown",
                    string(row.get("severity"), 20) or "unknown",
                    int(confidence) if confidence is not None else None,
                    stamp(row.get("first_seen")),
                    stamp(row.get("last_seen")),
                    stamp(row.get("expires_at")),
                    string(row.get("family"), 120),
                    reference,
                    import_id,
                ),
            )
        for row in cves:
            cve = string(row.get("cve"), 32).upper()
            if not CVE.fullmatch(cve):
                raise InspectorError("CVE tidak valid pada paket endpoint.")
            products = row.get("products") or []
            if not isinstance(products, list) or len(products) > 100:
                raise InspectorError("Daftar CPE pada paket tidak valid.")
            fields = (
                "vendor",
                "product",
                "version",
                "start_including",
                "start_excluding",
                "end_including",
                "end_excluding",
                "cpe",
            )
            products = [
                {key: string(product.get(key), 250) for key in fields}
                for product in products
                if isinstance(product, dict)
            ]
            metadata = {
                "products": products,
                "description": string(row.get("description"), 3000),
                "required_action": string(row.get("required_action"), 1800),
                "weaknesses": [
                    item
                    for item in (row.get("weaknesses") if isinstance(row.get("weaknesses"), list) else [])[
                        :30
                    ]
                    if isinstance(item, str) and re.fullmatch(r"CWE-\d{1,7}", item)
                ],
            }
            c.exec_driver_sql(
                """INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve) DO UPDATE SET vendor=excluded.vendor,product=excluded.product,cvss=excluded.cvss,
                    severity=excluded.severity,kev_added=excluded.kev_added,kev_due=excluded.kev_due,epss=excluded.epss,
                    epss_on=excluded.epss_on,metadata=excluded.metadata,import_id=excluded.import_id""",
                (
                    cve,
                    string(row.get("vendor")),
                    string(row.get("product")),
                    fraction(row.get("cvss"), 10),
                    string(row.get("severity"), 20),
                    string(row.get("kev_added"), 10),
                    string(row.get("kev_due"), 10),
                    fraction(row.get("epss"), 1),
                    string(row.get("epss_on"), 10),
                    json_text(metadata),
                    import_id,
                ),
            )
            c.exec_driver_sql("DELETE FROM affected_products WHERE cve=?", (cve,))
            indexed = [
                (canonical_product(metadata["vendor"]), canonical_product(metadata["product"]))
                for metadata in products
            ]
            indexed.append(
                (canonical_product(string(row.get("vendor"))), canonical_product(string(row.get("product"))))
            )
            for vendor, product in set(indexed):
                if vendor and product:
                    c.exec_driver_sql("INSERT INTO affected_products VALUES (?,?,?)", (cve, vendor, product))
        for row in advisories:
            title, publisher = string(row.get("title"), 220), string(row.get("publisher"), 120)
            if not title or not publisher:
                raise InspectorError("Judul dan penerbit advisori wajib.")
            reference = string(row.get("reference"), 1000)
            published = string(row.get("published"), 10)
            reference_id = sha256(json_text([publisher, title, published, reference]).encode()).hexdigest()
            cve = string(row.get("cve"), 32).upper()
            c.exec_driver_sql(
                """INSERT INTO advisories VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(reference_id) DO UPDATE SET
                summary=excluded.summary,cve=excluded.cve,import_id=excluded.import_id""",
                (
                    reference_id,
                    publisher,
                    title,
                    published,
                    string(row.get("summary"), 3000),
                    cve if CVE.fullmatch(cve) else None,
                    reference,
                    import_id,
                ),
            )
        result = {"indicators": len(iocs), "vulnerabilities": len(cves), "advisories": len(advisories)}
        db.audit(c, None, "intel_imported", result)
        return result


def updated(db: Database) -> dict | None:
    return db.one(
        "SELECT source,imported_at,source_updated_at FROM intelligence_imports ORDER BY id DESC LIMIT 1"
    )


def lookup(db: Database, raw: str) -> Observation:
    kind, fingerprint, value, host = indicator(raw)
    matches = []
    if kind == "cve":
        result = db.one("SELECT * FROM vulnerabilities WHERE cve=?", (value,))
        if result:
            result["metadata"] = json.loads(result["metadata"])
            matches.append(result)
    else:
        terms = [(kind, fingerprint, "indikator persis")]
        if kind == "url" and host:
            related_kind, related_key, _, _ = indicator(host)
            terms.append((related_kind, related_key, "hostname URL"))
        for term, key, basis in terms:
            rows = db.rows(
                """SELECT i.display_value,i.source,i.severity,i.category,i.confidence,i.first_seen,i.last_seen,i.expires_at,i.family,i.reference,
                d.source_updated_at,d.imported_at FROM indicators i JOIN intelligence_imports d ON i.import_id=d.id
                WHERE kind=? AND fingerprint=? AND (expires_at IS NULL OR expires_at>?) ORDER BY i.confidence DESC,i.source LIMIT 25""",
                (term, key, now()),
            )
            matches.extend(row | {"basis": basis} for row in rows)
    findings = ()
    if matches:
        findings = (
            Finding(
                "threat_intelligence_match",
                "Indikator cocok dengan katalog lokal",
                "medium",
                "Tinjau provenance, tanggal observasi, dan konteks aset. Kecocokan sumber bukan penetapan kompromi.",
            ),
        )
    return Observation(
        "Basis data intelijen lokal",
        {
            "type": kind,
            "indicator": value,
            "matches": matches,
            "catalog": updated(db),
            "notice": "Katalog lokal dapat tidak lengkap. Ketiadaan kecocokan bukan bukti keamanan.",
        },
        findings,
    )


def family_or_advisory(db: Database, query: str) -> dict:
    text = string(query, 120)
    if not text:
        raise InspectorError("Masukkan nama keluarga malware atau advisori.")
    return {
        "families": db.rows(
            """SELECT family,source,COUNT(*) AS observations,MAX(last_seen) AS last_seen FROM indicators
        WHERE family LIKE ? GROUP BY family,source ORDER BY observations DESC LIMIT 50""",
            (f"%{text}%",),
        ),
        "advisories": db.rows(
            """SELECT publisher,title,published_at,cve,summary,reference FROM advisories
        WHERE title LIKE ? OR publisher LIKE ? OR cve=? ORDER BY published_at DESC LIMIT 50""",
            (f"%{text}%", f"%{text}%", text.upper()),
        ),
    }


def canonical_product(text: str) -> str:
    return " ".join(text.casefold().replace("_", " ").split())


def version_match(installed: str, cpe: dict) -> bool | None:
    specific = cpe.get("version") or "*"
    exact = specific not in ("*", "-")
    if exact and installed != specific:
        return False
    bounds = [
        (name, cpe.get(name))
        for name in ("start_including", "start_excluding", "end_including", "end_excluding")
        if cpe.get(name)
    ]
    if not bounds:
        return True if exact else None
    if not NUM_VERSION.fullmatch(installed) or any(not NUM_VERSION.fullmatch(value) for _, value in bounds):
        return None

    def version(value):
        parts = tuple(int(part) for part in value.split("."))
        return parts + (0,) * (13 - len(parts))

    current = version(installed)
    verdict = {
        "start_including": lambda bound: current >= bound,
        "start_excluding": lambda bound: current > bound,
        "end_including": lambda bound: current <= bound,
        "end_excluding": lambda bound: current < bound,
    }
    return all(verdict[name](version(value)) for name, value in bounds)


def assess(db: Database, products: list[Product]) -> Observation:
    results = []
    findings = []
    for item in products[:500]:
        vendor, product = canonical_product(item.vendor), canonical_product(item.name)
        matches = db.rows(
            """SELECT v.* FROM affected_products p JOIN vulnerabilities v ON v.cve=p.cve
            WHERE p.vendor=? AND p.product=? ORDER BY v.cvss DESC,v.cve LIMIT 100""",
            (vendor, product),
        )
        for row in matches:
            metadata = json.loads(row.pop("metadata"))
            cpes = [
                cpe
                for cpe in metadata["products"]
                if canonical_product(cpe["vendor"]) == vendor and canonical_product(cpe["product"]) == product
            ]
            decisions = [version_match(item.version, cpe) for cpe in cpes]
            if decisions and all(value is False for value in decisions):
                continue
            verified_version = True in decisions
            results.append(
                {
                    "product": item.model_dump(),
                    "vulnerability": row,
                    "version_match": verified_version,
                    "status": "potensial" if verified_version else "belum_diverifikasi",
                    "basis": "Nama vendor, produk dan rentang versi CPE"
                    if verified_version
                    else "Nama vendor dan produk; versi belum dapat divalidasi",
                    "matched_cpes": [entry["cpe"] for entry, matched in zip(cpes, decisions) if matched],
                    "cwe": metadata["weaknesses"],
                    "recommendation": metadata["required_action"]
                    or "Periksa advisori resmi vendor dan patch untuk versi yang sama.",
                }
            )
            if verified_version and len(findings) < 50:
                findings.append(
                    Finding(
                        "vulnerable_software",
                        f"Kandidat {row['cve']} pada {item.name}",
                        "high" if row["kev_added"] else "medium",
                        "Verifikasi kondisi CPE lengkap dan patch vendor. Tetapkan mitigasi melalui petugas berwenang.",
                    )
                )
            if len(results) >= 200:
                break
        if len(results) >= 200:
            break
    return Observation(
        "Pencocokan katalog kerentanan lokal dan rentang CPE",
        {
            "products_examined": min(len(products), 500),
            "candidates": results,
            "catalog": updated(db),
            "limitations": "Kombinasi platform CPE dan status patch aktual memerlukan verifikasi teknis.",
        },
        tuple(findings),
    )
