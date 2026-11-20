import json
from hashlib import sha256
from threading import Event

import pytest
from pydantic import ValidationError

from sentinel_inspector import backup, reporting
from sentinel_inspector.database import Database, InspectorError
from sentinel_inspector.models import Asset, Authorization, MobileCheck, Module
from sentinel_inspector.posture import evaluate
from sentinel_inspector.workflow import Selection, run


def authorized(db, modules, platform="android", local=False):
    asset = db.add_asset(
        Asset(code="TEST-01", name="TEST Institutional device", unit="TEST Lab", platform=platform)
    )
    return Authorization(
        asset_id=asset,
        operator_code="TEST.OP",
        reference="TEST-AUTH-1",
        scope="TEST approved configuration and selected fixtures",
        authorized=True,
        modules=modules,
        local_host_confirmed=local,
    )


def test_migration_up_down_and_fk(tmp_path):
    db = Database(tmp_path / "db.sqlite3")
    assert db.one("PRAGMA user_version")["user_version"] == 3
    assert len(db.rows("PRAGMA foreign_key_check")) == 0
    with db.write() as c:
        db._migration(c, "003_rollback.sql")
        db._migration(c, "002_rollback.sql")
        db._migration(c, "001_rollback.sql")
    db.engine.dispose()
    again = Database(tmp_path / "db.sqlite3")
    assert again.one("PRAGMA user_version")["user_version"] == 3
    assert again.verify_audit()


def test_migration_lock_reports_disposable_database(tmp_path):
    first = Database(tmp_path / "db.sqlite3")
    other = Database(first.path)
    with first.write():
        with other.engine.connect() as c:
            c.exec_driver_sql("PRAGMA busy_timeout=1")
        with pytest.raises(InspectorError, match="sedang digunakan"):
            with other.write():
                pytest.fail("acquired occupied write lock")


def test_scope_requires_affirmative_authorization_and_local_host(db):
    request = authorized(db, [Module.WINDOWS], "windows")
    with pytest.raises(ValidationError):
        Authorization.model_validate(request.model_dump() | {"authorized": False})
    with pytest.raises(InspectorError, match="komputer Windows"):
        db.create(request)
    unauthorized = request.model_copy(update={"modules": [Module.IOS]})
    with pytest.raises(InspectorError, match="di luar kategori"):
        db.create(unauthorized)


def test_closed_report_preserves_preceding_revision(db, tmp_path):
    session = db.create(authorized(db, [Module.ANDROID]))
    checks = (MobileCheck(control="screen_lock", state="fail"),)
    run(db, session, Selection({Module.ANDROID}, mobile_checks=checks), Event())
    db.close(session, "TEST.REV")
    previous = reporting.document(db, session, "complete")
    first = reporting.export(db, session, "complete", tmp_path / "first.pdf")
    finding = previous["findings"][0]["id"]
    with pytest.raises(InspectorError, match="alasan"):
        db.review_finding(finding, "resolved", "TEST.REV", "")
    db.review_finding(finding, "resolved", "TEST.REV", "TEST resolved after close")
    latest = reporting.document(db, session, "complete")
    assert latest["document"].endswith("-R2")
    assert latest["findings"][0]["status"] == "resolved"
    assert reporting.document(db, session, "complete", 1) == previous
    assert reporting.export(db, session, "complete", tmp_path / "again.pdf", 1) == first
    assert db.verify_audit()


def test_recover_interrupted_session_keeps_finished_evidence(db):
    from sentinel_inspector.platforms import mobile

    modules = {Module.ANDROID, Module.FILES}
    session = db.create(authorized(db, list(modules)))
    with db.session_lock(session):
        db.start(session, modules)
        db.running(session, Module.ANDROID)
        observation = mobile("android", (MobileCheck(control="screen_lock", state="pass"),))
        db.finish_task(session, Module.ANDROID, "complete", "TEST complete", [observation])
        db.running(session, Module.FILES)
        with pytest.raises(InspectorError, match="proses lain"):
            Database(db.path).recover_interrupted(session)
    reopened = Database(db.path)
    reopened.recover_interrupted(session)
    record = reopened.session(session)
    assert record["status"] == "review"
    assert {entry["module"]: entry["status"] for entry in record["tasks"]} == {"android": "complete", "files": "failed"}
    assert len(record["evidence"]) == 1 and record["evidence"][0]["verified_integrity"]
    reopened.close(session, "TEST.REV")
    assert reopened.report_revision(session, 1)["record"]["evidence"] == record["evidence"]


def test_workspace_reports_audit_and_mobile_findings(db, tmp_path):
    modules = {Module.ANDROID, Module.FILES}
    session = db.create(authorized(db, list(modules)))
    text = tmp_path / "dummy.exe"
    text.write_text("TEST Plain text", encoding="utf-8")
    progress = []
    run(
        db,
        session,
        Selection(
            modules,
            (text,),
            (
                MobileCheck(control="support", state="pass"),
                MobileCheck(control="os_updates", state="pass"),
                MobileCheck(control="storage_encryption", state="pass"),
                MobileCheck(control="play_protect", state="pass"),
                MobileCheck(control="screen_lock", state="fail", note="TEST demonstrasi risiko"),
            ),
        ),
        Event(),
        lambda name, count, total, notice: progress.append((name, count, total, notice)),
    )
    record = db.session(session)
    assert record["status"] == "review"
    assert all(item["verified_integrity"] for item in record["evidence"])
    findings = {item["category"] for item in record["findings"]}
    assert {"mobile_configuration", "suspicious_file_signature"} <= findings
    rule = db.one("SELECT * FROM scoring_rules")
    posture = evaluate(record, rule)
    assert posture["coverage"] == 85 and posture["score"] == 82
    assert progress[-1][1:3] == (2, 2)
    for fmt in ("pdf", "json", "csv"):
        output = tmp_path / f"report.{fmt}"
        checksum = reporting.export(db, session, "complete", output)
        assert checksum == sha256(output.read_bytes()).hexdigest()
        if fmt == "pdf":
            assert output.read_bytes().startswith(b"%PDF")
        if fmt == "json":
            assert json.loads(output.read_bytes())["session"]["asset_code"] == "TEST-01"
    db.review_finding(record["findings"][0]["id"], "verified", "TEST.REV", "TEST verified")
    db.close(session, "TEST.REV")
    assert db.session(session)["status"] == "closed"
    assert db.verify_audit()
    with db.write() as c:
        c.exec_driver_sql("UPDATE audit_events SET event='modified' WHERE sequence=1")
        c.exec_driver_sql(
            "UPDATE technical_evidence SET payload='not-json' WHERE inspection_id=?", (session,)
        )
    assert db.verify_audit() is False
    assert all(not item["verified_integrity"] for item in db.session(session)["evidence"])


def test_cancellation_and_incomplete_coverage(db):
    session = db.create(authorized(db, [Module.IOS], "ios"))
    cancel = Event()
    cancel.set()
    run(db, session, Selection({Module.IOS}), cancel)
    record = db.session(session)
    assert record["status"] == "cancelled" and record["tasks"][0]["status"] == "cancelled"
    result = evaluate(record, db.one("SELECT * FROM scoring_rules"))
    assert result["score"] is None and result["coverage"] == 0
    assert result["controls"]["antivirus"]["state"] == "not_applicable"


def test_restore_authentication_and_exclusive_file(db, tmp_path):
    authorized(db, [Module.IOS], "ios")
    protected = tmp_path / "backup.psi"
    secret = "TEST passphrase private only"
    checksum = backup.create(db, protected, secret)
    assert protected.read_bytes().startswith(b"PSI-BKP1") and b"TEST-01" not in protected.read_bytes()
    restored = tmp_path / "restore.sqlite3"
    with pytest.raises(InspectorError, match="Integritas"):
        backup.restore(protected, restored, "TEST different incorrect password")
    assert not restored.exists()
    assert backup.restore(protected, restored, secret) == checksum
    assert Database(restored).counts()["assets"] == 1
    with pytest.raises(InspectorError, match="sudah ada"):
        backup.restore(protected, restored, secret)


def test_scoring_changes_preserve_existing_session_rule(db):
    request = authorized(db, [Module.ANDROID])
    old = db.create(request)
    initial = json.loads(db.score_rule()["weights"])
    weights = initial | {"os": 30, "mitigation": 5}
    version = db.configure_scoring(weights, 80)
    new = db.create(request)
    assert db.session(old)["scoring_rule"] == "posture-1"
    assert db.session(new)["scoring_rule"] == version
    assert db.score_rule(version)["minimum_coverage"] == 80
    with pytest.raises(InspectorError):
        db.configure_scoring(weights | {"os": 31}, 80)
