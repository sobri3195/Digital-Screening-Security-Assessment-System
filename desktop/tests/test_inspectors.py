from base64 import b64encode
from hashlib import sha256
import json
import struct
from threading import Event
from zipfile import ZipFile

import pytest

from sentinel_inspector import apk, engines, intelligence, platforms
from sentinel_inspector.database import InspectorError
from sentinel_inspector.file_inspection import Cancelled, inspect
from sentinel_inspector.models import Product


def test_hash_signatures_and_bounded_archive(tmp_path):
    technical = tmp_path / "test.txt"
    data = b"%PDF-1.4\nTEST\n"
    technical.write_bytes(data)
    result = inspect(technical, Event()).observation()
    assert result.payload["format"] == "pdf" and result.payload["extension_mismatch"]
    assert result.payload["hashes"]["sha256"] == sha256(data).hexdigest()
    archive = tmp_path / "test.zip"
    with ZipFile(archive, "w") as content:
        content.writestr("../TEST-no-extraction.txt", "TEST fixture")
    inspected = inspect(archive, Event())
    assert inspected.archive["unsafe_names"] == 1
    assert not (tmp_path.parent / "TEST-no-extraction.txt").exists()


def test_cancel_and_broken_zip(tmp_path):
    source = tmp_path / "test.zip"
    source.write_bytes(b"PK\x03\x04broken")
    assert inspect(source, Event()).structural_issue
    stopped = Event()
    stopped.set()
    with pytest.raises(Cancelled):
        inspect(source, stopped)


def test_symlink_rejected(tmp_path):
    file = tmp_path / "one"
    file.write_text("Test")
    link = tmp_path / "link"
    try:
        link.symlink_to(file)
    except OSError:
        pytest.skip("OS file symlinks unavailable for current account")
    with pytest.raises(InspectorError):
        inspect(link, Event())


def test_apk_static_manifest_and_ambiguous_archive(tmp_path):
    path = tmp_path / "test.apk"
    with ZipFile(path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.sentinel">'
            '<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34"/>'
            '<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/></manifest>',
        )
    result = apk.inspect_apk(path, Event())
    assert result.payload["package"] == "test.sentinel"
    assert result.payload["target_sdk"] == "34"
    assert result.findings[0].category == "apk_permissions_review"
    assert result.payload["certificates"] == []
    with pytest.raises(InspectorError):
        apk.parse_manifest(
            b'<!DOCTYPE manifest SYSTEM "file:///etc/passwd"><manifest package="test.sentinel"/>'
        )
    broken = tmp_path / "broken.apk"
    with ZipFile(broken, "w") as archive:
        archive.writestr("other.txt", "TEST")
    with pytest.raises(InspectorError, match="tepat satu"):
        apk.inspect_apk(broken, Event())


def test_binary_manifest():
    strings = ["manifest", "package", "test.sentinel", "uses-sdk", "targetSdkVersion"]
    data, offsets = bytearray(), []
    for text in strings:
        offsets.append(len(data))
        encoded = text.encode()
        data += bytes([len(text), len(encoded)]) + encoded + b"\x00"
    pool = struct.pack(
        "<HHIIIIII", 1, 28, 28 + len(offsets) * 4 + len(data), len(offsets), 0, 256, 28 + len(offsets) * 4, 0
    )
    pool += struct.pack("<" + "I" * len(offsets), *offsets) + data

    def element(tag, key, value, kind, raw):
        header = struct.pack("<HHIII", 0x0102, 16, 56, 1, 0xFFFFFFFF)
        extension = struct.pack("<IIHHHHHH", 0xFFFFFFFF, tag, 20, 20, 1, 0, 0, 0)
        entry = struct.pack("<IIIHBBI", 0xFFFFFFFF, key, raw, 8, 0, kind, value)
        return header + extension + entry

    root = pool + element(0, 1, 2, 3, 2) + element(3, 4, 34, 0x10, 0xFFFFFFFF)
    result = apk.parse_manifest(struct.pack("<HHI", 3, 8, 8 + len(root)) + root)
    assert result["package"] == "test.sentinel" and result["target_sdk"] == "34"
    with pytest.raises(InspectorError):
        apk.parse_manifest(root[:-1])


def test_usb_events_hide_device_identifiers(db):
    one = {
        "PNPDeviceID": "USB\\VID_1111&PID_1234\\TEST-PRIVATE-SERIAL",
        "Name": "Android TEST Device",
        "Manufacturer": "TEST Manufacturer",
        "PNPClass": "USB",
        "Service": "WinUSB",
        "ConfigManagerErrorCode": 0,
    }
    cycles = iter([[one], [], [one | {"ConfigManagerErrorCode": 28}]])
    monitor = platforms.UsbMonitor(db, lambda *_: next(cycles))
    assert monitor.poll(Event())[0].category == "android"
    assert monitor.poll(Event()) == []
    assert monitor.poll(Event())[0].driver_status == "driver_bermasalah"
    rows = db.rows("SELECT * FROM usb_events ORDER BY id")
    assert [row["event"] for row in rows] == ["connected", "disconnected", "connected"]
    assert "TEST-PRIVATE-SERIAL" not in json.dumps(rows)


def test_windows_fixture_reports_known_and_unknown_controls():
    source = {
        "os_version": "10.0.26100",
        "firewall": [{"Name": "Public", "Enabled": False}],
        "defender_antivirus": None,
        "smb_v1": True,
    }
    result = platforms.security(Event(), lambda *_: source.copy())
    assert [item.category for item in result.findings] == ["weak_firewall", "legacy_protocol"]
    assert result.payload["password_policy"].startswith("Tidak diverifikasi")
    assert result.payload["defender_antivirus"] is None
    with pytest.raises(platforms.Unavailable):
        platforms.security(Event(), lambda *_: {})


def test_malware_engine_unavailable_never_reports_clean(monkeypatch, tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("TEST", encoding="utf-8")
    monkeypatch.setattr(engines.shutil, "which", lambda _: None)
    monkeypatch.setattr(engines, "_defender_path", lambda: None)
    assert engines.clam_scan(file, Event())["status"] == "unavailable"
    assert engines.defender_scan(file, Event())["status"] == "unavailable"


def test_defender_rejects_cloud_submission(monkeypatch, tmp_path):
    file = tmp_path / "sample.txt"
    file.write_text("TEST", encoding="utf-8")
    monkeypatch.setattr(engines, "_defender_path", lambda: tmp_path / "1.0" / "MpCmdRun.exe")
    monkeypatch.setattr(engines, "powershell", lambda *_: {"cloud": 2, "sample": 1})
    monkeypatch.setattr(engines, "command", lambda *_: pytest.fail("Defender should not start"))
    assert engines.defender_scan(file, Event())["status"] == "unavailable"


def test_yara_against_inert_fixture_and_rule_toggle(db, tmp_path):
    pytest.importorskip("yara")
    path = tmp_path / "test.yar"
    path.write_text(
        'rule TEST_SENTINEL { strings: $x = "benign-sentinel-test" condition: $x }', encoding="utf-8"
    )
    test = tmp_path / "sample.txt"
    test.write_text("benign-sentinel-test", encoding="utf-8")
    code = engines.register_rule(db, path, "TEST rules", "1")
    assert engines.yara_scan(db, test, Event())["status"] == "unavailable"
    engines.toggle_rule(db, code, True)
    scan = engines.yara_scan(db, test, Event())
    assert scan["status"] == "review" and scan["matches"][0]["rule"] == "TEST_SENTINEL"
    with pytest.raises(InspectorError):
        engines.compile_rules('include "private_file.yar"')


def bundle(path, name, records):
    payload = b64encode(json.dumps(records).encode()).decode()
    path.write_text(
        json.dumps({"format": name, "payload": payload, "sha256": sha256(payload.encode()).hexdigest()}),
        encoding="utf-8",
    )
    return path


def test_phase_two_package_and_offline_correlation(db, tmp_path):
    path = bundle(
        tmp_path / "ioc.json",
        "sentinel-ioc-v1",
        [
            {
                "value": "test[.]example[.]test",
                "category": "malware",
                "last_seen": "2025-11-15T12:00:00+07:00",
                "confidence": 80,
                "origin_provider": "TEST Feed",
                "family": "TEST family",
            }
        ],
    )
    assert intelligence.load_package(db, path)["indicators"] == 1
    assert intelligence.load_package(db, path)["already_imported"]
    result = intelligence.lookup(db, "https://test.example.test/hello?secret=yes")
    assert result.payload["matches"][0]["basis"] == "hostname URL"
    assert "secret" not in result.payload["indicator"]
    assert intelligence.family_or_advisory(db, "TEST family")["families"]
    expired = bundle(
        tmp_path / "expired.json",
        "sentinel-ioc-v1",
        [{"value": "expired[.]test", "expires_at": "2020-01-01T00:00:00Z"}],
    )
    intelligence.load_package(db, expired)
    assert not intelligence.lookup(db, "expired.test").payload["matches"]
    path.write_text(path.read_text().replace("sha256", "sha256_changed"))
    with pytest.raises(InspectorError, match="checksum"):
        intelligence.load_package(db, path)


def test_version_matching_requires_vendor_product_and_range(db, tmp_path):
    path = bundle(
        tmp_path / "endpoint.json",
        "sentinel-endpoint-v1",
        {
            "vulnerabilities": [
                {
                    "cve": "CVE-2099-12345",
                    "vendor": "TEST Vendor",
                    "product": "TEST App",
                    "cvss": "8.8",
                    "severity": "high",
                    "products": [
                        {
                            "vendor": "test_vendor",
                            "product": "test_app",
                            "version": "*",
                            "start_including": "1.0",
                            "end_excluding": "2.0",
                        }
                    ],
                }
            ],
            "advisories": [{"title": "TEST notice", "publisher": "TEST source", "cve": "CVE-2099-12345"}],
            "source_updated_at": "2025-07-21T12:00:00Z",
        },
    )
    intelligence.load_package(db, path)
    found = intelligence.assess(db, [Product(vendor="TEST Vendor", name="TEST App", version="1.9")])
    assert found.payload["candidates"][0]["status"] == "potensial"
    assert found.findings
    assert not intelligence.assess(
        db, [Product(vendor="TEST Vendor", name="TEST App", version="2.0")]
    ).payload["candidates"]
    assert not intelligence.assess(
        db, [Product(vendor="Another vendor", name="TEST App", version="1.9")]
    ).payload["candidates"]
    assert intelligence.family_or_advisory(db, "CVE-2099-12345")["advisories"]
