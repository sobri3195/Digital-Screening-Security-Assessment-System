from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from importlib.resources import files
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from sqlalchemy import URL, create_engine, event
from sqlalchemy.exc import OperationalError

from .models import Asset, Authorization, COMMON_MODULES, Module, Observation, PLATFORM_MODULES, Platform
from .posture import evaluate


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def json_text(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def digest(value) -> str:
    return sha256(json_text(value).encode()).hexdigest()


class InspectorError(Exception):
    """An error with a message that is safe to display."""


class Database:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        existed = self.path.exists()
        if not existed:
            try:
                self.path.touch(mode=0o600, exist_ok=False)
            except FileExistsError:
                pass
        self.engine = create_engine(
            URL.create("sqlite+pysqlite", database=str(self.path)), connect_args={"timeout": 4}
        )

        @event.listens_for(self.engine, "connect")
        def configure(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA busy_timeout=4000")

        with self.write() as c:
            version = c.exec_driver_sql("PRAGMA user_version").scalar_one()
            if version not in range(4):
                raise InspectorError("Versi basis data lebih baru dari aplikasi ini.")
            for target, filename in ((1, "001_initial.sql"), (2, "002_scoring_settings.sql"), (3, "003_report_revisions.sql")):
                if version < target:
                    self._migration(c, filename)
            if version < 3:
                for session in c.exec_driver_sql("SELECT id FROM inspections WHERE status='closed'").scalars().all():
                    self._freeze_report(c, session, legacy=True)

    @staticmethod
    def _migration(connection, name: str):
        script = files("sentinel_inspector").joinpath("migrations", name).read_text(encoding="utf-8")
        statement = ""
        for line in script.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                connection.exec_driver_sql(statement)
                statement = ""
        if statement.strip():
            raise InspectorError("Migrasi SQL tidak lengkap.")

    @contextmanager
    def write(self):
        with self.engine.connect() as c:
            try:
                c.exec_driver_sql("BEGIN IMMEDIATE")
                yield c
                c.commit()
            except OperationalError as error:
                c.rollback()
                if isinstance(error.orig, sqlite3.OperationalError) and getattr(
                    error.orig, "sqlite_errorcode", 0
                ) in (5, 6):
                    raise InspectorError(
                        "Basis data sedang digunakan. Coba kembali setelah pekerjaan lain selesai."
                    ) from error
                raise
            except Exception:
                c.rollback()
                raise

    def rows(self, sql: str, args=()) -> list[dict]:
        with self.engine.connect() as c:
            return [dict(row) for row in c.exec_driver_sql(sql, args).mappings()]

    def one(self, sql: str, args=()) -> dict | None:
        with self.engine.connect() as c:
            row = c.exec_driver_sql(sql, args).mappings().first()
            return dict(row) if row else None

    @staticmethod
    def audit(c, session: str | None, kind: str, detail: dict, when: str | None = None):
        previous = c.exec_driver_sql(
            "SELECT sequence,sha256 FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).first()
        seq, prev = (previous[0] + 1, previous[1]) if previous else (1, "0" * 64)
        when = when or now()
        checksum = digest([seq, session, kind, detail, when, prev])
        c.exec_driver_sql(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
            (seq, session, kind, json_text(detail), when, prev, checksum),
        )

    def add_asset(self, asset: Asset) -> str:
        with self.write() as c:
            asset_id = uuid4().hex
            insert = c.exec_driver_sql(
                "INSERT INTO assets VALUES (?,?,?,?,?,?) ON CONFLICT(code) DO NOTHING",
                (asset_id, asset.code, asset.name, asset.platform.value, asset.unit, now()),
            )
            if not insert.rowcount:
                raise InspectorError("Kode aset sudah terdaftar.")
            self.audit(c, None, "asset_registered", {"asset_id": asset_id})
        return asset_id

    def create(self, request: Authorization) -> str:
        asset = self.one("SELECT id,category FROM assets WHERE id=?", (request.asset_id,))
        if asset is None:
            raise InspectorError("Pilih aset institusi yang terdaftar.")
        allowed = COMMON_MODULES | PLATFORM_MODULES[Platform(asset["category"])]
        if not set(request.modules) <= allowed:
            raise InspectorError("Modul di luar kategori aset yang dipilih.")
        if set(request.modules) & {Module.WINDOWS, Module.SOFTWARE} and not request.local_host_confirmed:
            raise InspectorError(
                "Konfirmasikan bahwa aset adalah komputer Windows yang menjalankan aplikasi."
            )
        reference = uuid4().hex
        session_id = uuid4().hex
        timestamp = now()
        with self.write() as c:
            c.exec_driver_sql(
                "INSERT INTO inspection_authorizations VALUES (?,?,?,?,?,?,?)",
                (
                    reference,
                    asset["id"],
                    request.operator_code,
                    request.reference,
                    request.scope,
                    timestamp,
                    int(request.local_host_confirmed),
                ),
            )
            scoring = c.exec_driver_sql(
                "SELECT value FROM inspector_settings WHERE name='active_scoring_rule'"
            ).scalar_one()
            c.exec_driver_sql(
                "INSERT INTO inspections (id, authorization_id, mode, status, created_at, scoring_rule) VALUES (?,?,?,?,?,?)",
                (session_id, reference, request.mode, "ready", timestamp, scoring),
            )
            for module in request.modules:
                c.exec_driver_sql(
                    "INSERT INTO inspection_tasks (inspection_id,module,status,updated_at) VALUES (?,?,?,?)",
                    (session_id, module.value, "pending", timestamp),
                )
            self.audit(c, session_id, "session_created", {"mode": request.mode}, timestamp)
            self.audit(c, session_id, "authorization_verified", {"reference": request.reference}, timestamp)
        return session_id

    def start(self, session: str, modules: set[Module]):
        with self.write() as c:
            expected = {
                row[0]
                for row in c.exec_driver_sql(
                    "SELECT module FROM inspection_tasks WHERE inspection_id=? AND status='pending'",
                    (session,),
                )
            }
            if expected != {m.value for m in modules}:
                raise InspectorError("Modul yang dijalankan harus sama dengan otorisasi.")
            result = c.exec_driver_sql(
                "UPDATE inspections SET status='running',started_at=? WHERE id=? AND status='ready'",
                (now(), session),
            )
            if result.rowcount != 1:
                raise InspectorError("Sesi sudah dimulai atau tidak dapat dijalankan.")
            self.audit(c, session, "inspection_started", {"modules": sorted(expected)})

    def running(self, session: str, module: Module):
        with self.write() as c:
            result = c.exec_driver_sql(
                "UPDATE inspection_tasks SET status='running',updated_at=? WHERE inspection_id=? AND module=? AND status='pending'",
                (now(), session, module.value),
            )
            if result.rowcount != 1:
                raise InspectorError("Modul belum diotorisasi atau sudah dijalankan.")

    def finish_task(
        self, session: str, module: Module, status: str, notice: str, observations: list[Observation]
    ):
        timestamp = now()
        with self.write() as c:
            result = c.exec_driver_sql(
                """UPDATE inspection_tasks SET status=?,notice=?,updated_at=?
                WHERE inspection_id=? AND module=? AND status='running'
                AND EXISTS (SELECT 1 FROM inspections WHERE id=? AND status='running')""",
                (status, notice, timestamp, session, module.value, session),
            )
            if result.rowcount != 1:
                raise InspectorError("Status sesi berubah. Bukti tidak ditulis.")
            for item in observations:
                token = uuid4().hex
                checksum = digest([token, session, module.value, item.source, timestamp, item.payload])
                c.exec_driver_sql(
                    "INSERT INTO technical_evidence VALUES (?,?,?,?,?,?,?)",
                    (token, session, module.value, item.source, timestamp, json_text(item.payload), checksum),
                )
                for finding in item.findings:
                    finding_id = uuid4().hex
                    c.exec_driver_sql(
                        """INSERT INTO findings (id,inspection_id,evidence_id,category,title,severity,status,recommendation,updated_at)
                        VALUES (?,?,?,?,?,?,'open',?,?)""",
                        (
                            finding_id,
                            session,
                            token,
                            finding.category,
                            finding.title,
                            finding.severity,
                            finding.recommendation,
                            timestamp,
                        ),
                    )
                    self.audit(c, session, "finding_detected", {"finding_id": finding_id}, timestamp)
            self.audit(
                c,
                session,
                "module_completed",
                {"module": module.value, "status": status, "evidence": len(observations)},
                timestamp,
            )

    def finish(self, session: str, cancelled: bool):
        timestamp = now()
        status = "cancelled" if cancelled else "review"
        with self.write() as c:
            result = c.exec_driver_sql(
                "UPDATE inspections SET status=?,ended_at=? WHERE id=? AND status='running'",
                (status, timestamp, session),
            )
            if result.rowcount != 1:
                raise InspectorError("Sesi tidak aktif.")
            if cancelled:
                c.exec_driver_sql(
                    "UPDATE inspection_tasks SET status='cancelled',updated_at=? WHERE inspection_id=? AND status IN ('pending','running')",
                    (timestamp, session),
                )
            self.audit(
                c,
                session,
                "inspection_cancelled" if cancelled else "inspection_ready_for_review",
                {},
                timestamp,
            )

    def close(self, session: str, reviewer: str):
        with self.write() as c:
            result = c.exec_driver_sql(
                "UPDATE inspections SET status='closed',reviewer_code=? WHERE id=? AND status='review'",
                (reviewer, session),
            )
            if result.rowcount != 1:
                raise InspectorError("Sesi belum siap ditutup.")
            self.audit(c, session, "session_completed", {"reviewer": reviewer})
            self._freeze_report(c, session)

    def review_finding(self, finding: str, status: str, reviewer: str, note: str):
        if status not in {"open", "pending", "verified", "false_positive", "mitigating", "resolved"}:
            raise InspectorError("Status temuan tidak valid.")
        with self.write() as c:
            linked = c.exec_driver_sql(
                "SELECT i.id,i.status FROM findings f JOIN inspections i ON i.id=f.inspection_id WHERE f.id=?",
                (finding,),
            ).first()
            if linked is None:
                raise InspectorError("Temuan tidak ditemukan.")
            if linked[1] == "closed" and (not note.strip() or not reviewer.strip()):
                raise InspectorError("Revisi sesi tertutup memerlukan peninjau dan alasan.")
            c.exec_driver_sql(
                "UPDATE findings SET status=?,reviewer_code=?,review_note=?,updated_at=? WHERE id=?",
                (status, reviewer, note, now(), finding),
            )
            self.audit(
                c,
                linked[0],
                "finding_reviewed",
                {"finding_id": finding, "status": status, "reviewer": reviewer},
            )
            if linked[1] == "closed":
                self._freeze_report(c, linked[0])

    def _freeze_report(self, c, session: str, legacy=False):
        record = self._session(c, session)
        revision = c.exec_driver_sql(
            "SELECT COALESCE(MAX(revision),0)+1 FROM inspection_report_revisions WHERE inspection_id=?", (session,)
        ).scalar_one()
        rule = dict(c.exec_driver_sql(
            "SELECT * FROM scoring_rules WHERE version=?", (record["scoring_rule"],)
        ).mappings().one())
        snapshot = {
            "revision": revision, "generated_at": now(), "legacy": legacy, "record": record,
            "posture": evaluate(record, rule), "usb": self._report_usb(c, record),
        }
        c.exec_driver_sql(
            "INSERT INTO inspection_report_revisions VALUES (?,?,?)", (session, revision, json_text(snapshot))
        )
        self.audit(c, session, "report_snapshot_saved", {"revision": revision, "legacy": legacy})

    def report_revision(self, session: str, revision: int | None) -> dict:
        row = self.one(
            """SELECT snapshot FROM inspection_report_revisions WHERE inspection_id=? AND (? IS NULL OR revision=?)
            ORDER BY revision DESC LIMIT 1""", (session, revision, revision)
        )
        if row is None:
            raise InspectorError("Revisi laporan tidak ditemukan.")
        return json.loads(row["snapshot"])

    def report_usb(self, record: dict) -> list[dict]:
        with self.engine.connect() as c:
            return self._report_usb(c, record)

    @staticmethod
    def _report_usb(c, record: dict) -> list[dict]:
        return [dict(row) for row in c.exec_driver_sql(
            """SELECT event,category,manufacturer,model,driver_status,observed_at FROM usb_events
            WHERE observed_at>=? AND observed_at<=? ORDER BY observed_at,id LIMIT 200""",
            (record["started_at"], record["ended_at"]),
        ).mappings()]

    def session(self, session: str) -> dict:
        with self.engine.connect() as c:
            return self._session(c, session)

    @staticmethod
    def _session(c, session: str) -> dict:
        def rows(statement, args):
            return [dict(row) for row in c.exec_driver_sql(statement, args).mappings()]

        matches = rows(
            """SELECT i.id,i.mode,i.status,i.created_at,i.started_at,i.ended_at,i.reviewer_code,i.scoring_rule,
            au.operator_code,au.reference,au.scope,au.local_host_confirmed,a.code AS asset_code,a.name AS asset_name,a.category AS platform,a.owner_unit
            FROM inspections i JOIN inspection_authorizations au ON au.id=i.authorization_id
            JOIN assets a ON a.id=au.asset_id WHERE i.id=?""",
            (session,),
        )
        if not matches:
            raise InspectorError("Sesi tidak ditemukan.")
        item = matches[0]
        item["tasks"] = rows(
            "SELECT module,status,notice,updated_at FROM inspection_tasks WHERE inspection_id=? ORDER BY rowid",
            (session,),
        )
        evidence = rows(
            "SELECT * FROM technical_evidence WHERE inspection_id=? ORDER BY observed_at,id", (session,)
        )
        for entry in evidence:
            try:
                entry["payload"] = json.loads(entry["payload"])
                entry["verified_integrity"] = (
                    digest(
                        [
                            entry["id"],
                            session,
                            entry["module"],
                            entry["source"],
                            entry["observed_at"],
                            entry["payload"],
                        ]
                    )
                    == entry["sha256"]
                )
            except (ValueError, TypeError):
                entry["payload"] = {"error": "Bukti tidak dapat dibaca."}
                entry["verified_integrity"] = False
        item["evidence"] = evidence
        item["findings"] = rows(
            "SELECT * FROM findings WHERE inspection_id=? ORDER BY updated_at,id", (session,)
        )
        item["timeline"] = rows(
            "SELECT sequence,event,occurred_at,detail,sha256 FROM audit_events WHERE inspection_id=? ORDER BY sequence",
            (session,),
        )
        return item

    def verify_audit(self) -> bool:
        previous = "0" * 64
        with self.engine.connect() as c:
            records = c.exec_driver_sql("SELECT * FROM audit_events ORDER BY sequence").mappings()
            for index, row in enumerate(records, start=1):
                if row["sequence"] != index or row["previous_sha256"] != previous:
                    return False
                try:
                    checksum = digest(
                        [
                            index,
                            row["inspection_id"],
                            row["event"],
                            json.loads(row["detail"]),
                            row["occurred_at"],
                            previous,
                        ]
                    )
                except (ValueError, TypeError):
                    return False
                if checksum != row["sha256"]:
                    return False
                previous = checksum
        return True

    def score_rule(self, version: str | None = None) -> dict:
        rule = self.one(
            """SELECT * FROM scoring_rules WHERE version=COALESCE(?,(SELECT value FROM inspector_settings
            WHERE name='active_scoring_rule'))""",
            (version,),
        )
        if not rule:
            raise InspectorError("Versi aturan posture tidak tersedia.")
        return rule

    def configure_scoring(self, weights: dict, minimum: int) -> str:
        if (
            not isinstance(weights, dict)
            or set(weights) != {"os", "updates", "antivirus", "encryption", "configuration", "mitigation"}
            or any(type(value) is not int or value < 0 or value > 100 for value in weights.values())
            or sum(weights.values()) != 100
            or type(minimum) is not int
            or not 50 <= minimum <= 100
        ):
            raise InspectorError("Bobot harus berjumlah 100. Cakupan minimum harus 50–100 persen.")
        version = "posture-" + digest([weights, minimum])[:12]
        with self.write() as c:
            c.exec_driver_sql(
                "INSERT INTO scoring_rules VALUES (?,?,?) ON CONFLICT(version) DO NOTHING",
                (version, json_text(weights), minimum),
            )
            c.exec_driver_sql(
                "UPDATE inspector_settings SET value=? WHERE name='active_scoring_rule'", (version,)
            )
            self.audit(c, None, "scoring_rule_changed", {"version": version})
        return version

    def retain_usb(self, days: int) -> int:
        if not 7 <= days <= 3650:
            raise InspectorError("Pilih retensi USB antara 7 dan 3.650 hari.")
        before = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
        with self.write() as c:
            deleted = c.exec_driver_sql("DELETE FROM usb_events WHERE observed_at<?", (before,)).rowcount
            self.audit(c, None, "usb_retention_applied", {"days": days, "deleted": deleted})
        return deleted

    def list_sessions(self) -> list[dict]:
        return self.rows("""SELECT i.id,a.code AS asset,i.mode,i.status,i.created_at FROM inspections i
            JOIN inspection_authorizations au ON i.authorization_id=au.id JOIN assets a ON a.id=au.asset_id
            ORDER BY i.created_at DESC LIMIT 200""")

    def counts(self) -> dict:
        return self.one("""SELECT (SELECT COUNT(*) FROM assets) AS assets,
            (SELECT COUNT(*) FROM inspections WHERE status='running') AS running,
            (SELECT COUNT(*) FROM inspections WHERE status IN ('review','closed')) AS complete,
            (SELECT COUNT(*) FROM findings WHERE status NOT IN ('resolved','false_positive')) AS findings,
            (SELECT COUNT(*) FROM vulnerabilities WHERE severity='critical') AS critical,
            (SELECT COUNT(*) FROM indicators WHERE category='malware') AS malware""")
