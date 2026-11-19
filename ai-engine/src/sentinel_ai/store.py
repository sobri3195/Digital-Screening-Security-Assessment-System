from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from importlib.resources import files
import json
from pathlib import Path
import re
import sqlite3
import time
from uuid import uuid4

from sqlalchemy import URL, create_engine, event
from sqlalchemy.exc import IntegrityError

from .schemas import TRUSTED_SOURCES, Document, ModelOptions
from .security import AccessError, Actor


def utc() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def j(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def checksum(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def chunk_text(text: str) -> list[str]:
    words = text.split()
    if not words:
        return []
    return [" ".join(words[index : index + 130])[:1600] for index in range(0, len(words), 105)][:100]


class Store:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.path.touch(mode=0o600, exist_ok=False)
        except FileExistsError:
            pass
        self.engine = create_engine(
            URL.create("sqlite+pysqlite", database=str(self.path)), connect_args={"timeout": 5}
        )

        @event.listens_for(self.engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")

        with self.write() as c:
            version = c.exec_driver_sql("PRAGMA user_version").scalar_one()
            if version == 0:
                text = (
                    files("sentinel_ai").joinpath("migrations", "001_initial.sql").read_text(encoding="utf-8")
                )
                partial = ""
                for line in text.splitlines(keepends=True):
                    partial += line
                    if sqlite3.complete_statement(partial):
                        c.exec_driver_sql(partial)
                        partial = ""
                if partial.strip():
                    raise ValueError("Invalid migration")
                for code, (title, _) in TRUSTED_SOURCES.items():
                    c.exec_driver_sql("INSERT INTO sources(code,title) VALUES (?,?)", (code, title))
            elif version != 1:
                raise ValueError("Unsupported AI database schema")

    @contextmanager
    def write(self):
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def rows(self, sql: str, args=()):
        with self.engine.connect() as c:
            return [dict(row) for row in c.exec_driver_sql(sql, tuple(args)).mappings()]

    def one(self, sql: str, args=()):
        with self.engine.connect() as c:
            row = c.exec_driver_sql(sql, tuple(args)).mappings().first()
            return dict(row) if row else None

    @staticmethod
    def audit(connection, actor: str, action: str, object_id: str | None, outcome="ok"):
        connection.exec_driver_sql(
            "INSERT INTO audit(actor,action,object_id,outcome,occurred_at) VALUES (?,?,?,?,?)",
            (checksum(actor)[:20], action, object_id, outcome, utc()),
        )

    def rate(self, actor: Actor):
        minute = int(time.time()) // 60
        with self.write() as c:
            seen = c.exec_driver_sql(
                """INSERT INTO limits VALUES(?,?,1) ON CONFLICT(actor,window) DO UPDATE SET count=count+1 RETURNING count""",
                (actor.subject, minute),
            ).scalar_one()
            if seen % 30 == 1:
                c.exec_driver_sql("DELETE FROM limits WHERE window<?", (minute - 10,))
        if seen > 180:
            raise AccessError(429, "rate_limited")

    def create_document(self, document: Document, actor: Actor) -> str:
        item = document.model_dump(mode="json")
        content = item.pop("content")
        content_hash = checksum(content)
        doc_id = uuid4().hex
        try:
            with self.write() as c:
                enabled = c.exec_driver_sql(
                    "SELECT enabled FROM sources WHERE code=?", (item["source"],)
                ).scalar_one()
                if not enabled:
                    raise AccessError(409, "source_disabled")
                c.exec_driver_sql(
                    """INSERT INTO documents(id,source_code,title,version,published,reference,classification,content,facts,checksum,submitted_by,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        doc_id,
                        item["source"],
                        item["title"],
                        item["version"],
                        item["published"],
                        item["reference"],
                        item["classification"],
                        content,
                        j(item["facts"]),
                        content_hash,
                        actor.subject,
                        utc(),
                        utc(),
                    ),
                )
                self.audit(c, actor.subject, "document_submitted", doc_id)
        except IntegrityError:
            raise AccessError(409, "duplicate_document") from None
        return doc_id

    def approve_document(self, doc_id: str, actor: Actor, embed=False) -> str | None:
        with self.write() as c:
            row = (
                c.exec_driver_sql(
                    """SELECT d.*,s.enabled FROM documents d JOIN sources s ON s.code=d.source_code WHERE d.id=?""",
                    (doc_id,),
                )
                .mappings()
                .first()
            )
            if not row:
                raise AccessError(404, "document_not_found")
            if row["state"] != "draft" or row["submitted_by"] == actor.subject or not row["enabled"]:
                raise AccessError(409, "approval_invalid")
            size = c.exec_driver_sql(
                """SELECT COUNT(*) FROM chunks c JOIN documents d ON d.id=c.document_id WHERE d.state='approved'"""
            ).scalar_one()
            parts = chunk_text(row["content"])
            if size + len(parts) > 5000:
                raise AccessError(409, "active_index_limit")
            for index, part in enumerate(parts):
                chunk_id = c.exec_driver_sql(
                    "INSERT INTO chunks(document_id,position,body) VALUES (?,?,?)", (doc_id, index, part)
                ).lastrowid
                c.exec_driver_sql("INSERT INTO chunks_fts(rowid,body) VALUES (?,?)", (chunk_id, part))
            c.exec_driver_sql(
                "UPDATE documents SET state='approved',index_status='keyword',approved_by=?,updated_at=? WHERE id=?",
                (actor.subject, utc(), doc_id),
            )
            self.audit(c, actor.subject, "document_approved", doc_id)
        return self.queue(actor, "index", {"document_id": doc_id}, priority=1) if embed else None

    def archive_document(self, doc_id: str, actor: Actor):
        with self.write() as c:
            current = c.exec_driver_sql("SELECT state FROM documents WHERE id=?", (doc_id,)).scalar()
            if current not in ("approved", "draft"):
                raise AccessError(404, "document_not_found")
            rows = c.exec_driver_sql("SELECT id,body FROM chunks WHERE document_id=?", (doc_id,)).mappings()
            for row in list(rows):
                c.exec_driver_sql(
                    "INSERT INTO chunks_fts(chunks_fts,rowid,body) VALUES('delete',?,?)",
                    (row["id"], row["body"]),
                )
            c.exec_driver_sql("DELETE FROM chunks WHERE document_id=?", (doc_id,))
            c.exec_driver_sql(
                "UPDATE documents SET state='archived',index_status='archived',updated_at=? WHERE id=?",
                (utc(), doc_id),
            )
            self.audit(c, actor.subject, "document_archived", doc_id)

    def set_source(self, source: str, enabled: bool, actor: Actor):
        with self.write() as c:
            if (
                c.exec_driver_sql(
                    "UPDATE sources SET enabled=? WHERE code=?", (int(enabled), source)
                ).rowcount
                != 1
            ):
                raise AccessError(404, "source_not_found")
            self.audit(c, actor.subject, "source_enabled" if enabled else "source_disabled", None)

    def approve_model(self, actor: Actor, name: str, kind: str, digest: str, license_reference: str) -> str:
        model = uuid4().hex
        try:
            with self.write() as c:
                c.exec_driver_sql(
                    """INSERT INTO models(id,name,digest,role,license_reference,options,approved_by,approved_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        model,
                        name,
                        digest,
                        kind,
                        license_reference,
                        ModelOptions().model_dump_json(),
                        actor.subject,
                        utc(),
                    ),
                )
                self.audit(c, actor.subject, "model_approved", model)
        except IntegrityError:
            raise AccessError(409, "duplicate_model") from None
        return model

    def select_model(self, actor: Actor, model: str, active: bool):
        with self.write() as c:
            selected = c.exec_driver_sql("SELECT role, enabled FROM models WHERE id=?", (model,)).first()
            if not selected or (active and not selected[1]):
                raise AccessError(404, "model_not_found")
            if active:
                c.exec_driver_sql("UPDATE models SET active=0 WHERE role=?", (selected[0],))
            c.exec_driver_sql("UPDATE models SET active=? WHERE id=?", (int(active), model))
            self.audit(c, actor.subject, "model_selected" if active else "model_deselected", model)

    def model_options(self, actor: Actor, model: str, options: ModelOptions):
        with self.write() as c:
            if (
                c.exec_driver_sql(
                    "UPDATE models SET options=? WHERE id=?", (options.model_dump_json(), model)
                ).rowcount
                != 1
            ):
                raise AccessError(404, "model_not_found")
            self.audit(c, actor.subject, "model_options_updated", model)

    def active(self, role: str):
        return self.one("SELECT * FROM models WHERE role=? AND enabled=1 AND active=1", (role,))

    def queue(self, actor: Actor, kind: str, payload: dict, priority=0) -> str:
        body = j(payload)
        hashed = checksum(body)
        job = uuid4().hex
        with self.write() as c:
            prior = c.exec_driver_sql(
                """SELECT id FROM jobs WHERE owner=? AND kind=? AND input_checksum=? AND state IN ('pending','processing')""",
                (actor.subject, kind, hashed),
            ).scalar()
            if prior:
                return prior
            capacity, owner_capacity = c.exec_driver_sql(
                """SELECT COUNT(*), SUM(CASE WHEN owner=? THEN 1 ELSE 0 END)
                FROM jobs WHERE state IN ('pending','processing')""",
                (actor.subject,),
            ).one()
            if capacity >= 100 or (owner_capacity or 0) >= 12:
                raise AccessError(429, "queue_full")
            c.exec_driver_sql(
                """INSERT INTO jobs(id,owner,kind,payload,input_checksum,state,created_at,updated_at,available_at,priority)
                VALUES(?,?,?,?,?,'pending',?,?,?,?)""",
                (job, actor.subject, kind, body, hashed, utc(), utc(), time.time(), priority),
            )
            self.audit(c, actor.subject, "job_enqueued", job)
        return job

    def claim(self, timeout: int, concurrency: int):
        curr = time.time()
        with self.write() as c:
            c.exec_driver_sql(
                """UPDATE jobs SET state=CASE WHEN cancel_requested=1 THEN 'cancelled' WHEN attempts>=2 THEN 'failed' ELSE 'pending' END,
                error_code=CASE WHEN cancel_requested=0 AND attempts>=2 THEN 'worker_timeout' ELSE NULL END,updated_at=?,lease=NULL,lease_until=NULL
                WHERE state='processing' AND lease_until<=?""",
                (utc(), curr),
            )
            ongoing = c.exec_driver_sql("SELECT COUNT(*) FROM jobs WHERE state='processing'").scalar_one()
            if ongoing >= concurrency:
                return None
            row = (
                c.exec_driver_sql(
                    """SELECT * FROM jobs WHERE state='pending' AND available_at<=?
                ORDER BY priority DESC,created_at LIMIT 1""",
                    (curr,),
                )
                .mappings()
                .first()
            )
            if not row:
                return None
            lease = uuid4().hex
            c.exec_driver_sql(
                "UPDATE jobs SET state='processing',attempts=attempts+1,lease=?,lease_until=?,updated_at=? WHERE id=?",
                (lease, curr + timeout + 10, utc(), row["id"]),
            )
            return dict(row) | {"lease": lease, "attempts": row["attempts"] + 1}

    def cancelled(self, job: dict) -> bool:
        row = self.one("SELECT cancel_requested,lease FROM jobs WHERE id=?", (job["id"],))
        return not row or row["cancel_requested"] == 1 or row["lease"] != job["lease"]

    def complete(
        self, job: dict, state: str, *, result=None, error=None, metrics=None, model=None, retry=False
    ):
        with self.write() as c:
            row = c.exec_driver_sql(
                "SELECT cancel_requested,lease FROM jobs WHERE id=?", (job["id"],)
            ).first()
            if not row or row[1] != job["lease"]:
                return
            state = "cancelled" if row[0] else ("pending" if retry and job["attempts"] < 2 else state)
            if row[0]:
                result = error = metrics = None
            c.exec_driver_sql(
                """UPDATE jobs SET state=?,result=?,error_code=?,metrics=?,model_name=?,model_digest=?,
                available_at=?,updated_at=?,lease=NULL,lease_until=NULL WHERE id=?""",
                (
                    state,
                    j(result) if result is not None else None,
                    error,
                    j(metrics) if metrics else None,
                    model["name"] if model else None,
                    model["digest"] if model else None,
                    time.time() + (3 if state == "pending" else 0),
                    utc(),
                    job["id"],
                ),
            )
            self.audit(c, job["owner"], "job_" + state, job["id"], error or "ok")

    def visible_job(self, actor: Actor, job: str):
        if not re.fullmatch(r"[a-f0-9]{32}", job):
            raise AccessError(404, "job_not_found")
        row = self.one(
            """SELECT id,owner,kind,state,created_at,updated_at,result,error_code,model_name,model_digest,metrics
            FROM jobs WHERE id=? AND (owner=? OR (?=1 AND kind NOT IN ('index','benchmark','evaluate')))""",
            (job, actor.subject, int("ai.report.review" in actor.scopes)),
        )
        if not row:
            raise AccessError(404, "job_not_found")
        for col in ("result", "metrics"):
            row[col] = json.loads(row[col]) if row[col] else None
        review = self.one(
            "SELECT decision,reviewed_at FROM reviews WHERE job_id=? ORDER BY id DESC LIMIT 1", (job,)
        )
        own = row.pop("owner") == actor.subject
        row["can_cancel"] = own and row["state"] in ("pending", "processing")
        row["can_review"] = (
            not own
            and "ai.report.review" in actor.scopes
            and bool(row["result"])
            and row["result"].get("status") == "draft"
        )
        if review and row["result"] and row["state"] in ("completed", "requires_review"):
            row["result"]["review_status"] = review["decision"]
        return row

    def cancel(self, actor: Actor, job: str):
        with self.write() as c:
            status = c.exec_driver_sql(
                "SELECT state FROM jobs WHERE id=? AND owner=?", (job, actor.subject)
            ).scalar()
            if status is None:
                raise AccessError(404, "job_not_found")
            if status not in ("pending", "processing"):
                raise AccessError(409, "job_finished")
            c.exec_driver_sql(
                """UPDATE jobs SET cancel_requested=1,updated_at=?,
                state=CASE WHEN state='pending' THEN 'cancelled' ELSE state END WHERE id=?""",
                (utc(), job),
            )
            self.audit(c, actor.subject, "cancel_requested", job)

    def review(self, actor: Actor, job: str, decision: str):
        with self.write() as c:
            entry = c.exec_driver_sql("SELECT owner,state,result,kind FROM jobs WHERE id=?", (job,)).first()
            if (
                not entry
                or entry[0] == actor.subject
                or entry[1] not in ("requires_review", "completed")
                or entry[3] in ("benchmark", "index", "evaluate")
            ):
                raise AccessError(409, "review_invalid")
            if decision == "verified" and (not entry[2] or json.loads(entry[2]).get("status") != "draft"):
                raise AccessError(409, "insufficient_evidence")
            state = "completed" if decision == "verified" else "requires_review"
            c.exec_driver_sql(
                "INSERT INTO reviews(job_id,reviewer,decision,reviewed_at) VALUES (?,?,?,?)",
                (job, actor.subject, decision, utc()),
            )
            c.exec_driver_sql("UPDATE jobs SET state=?,updated_at=? WHERE id=?", (state, utc(), job))
            self.audit(c, actor.subject, "review_" + decision, job)

    def purge(self, days: int, actor: Actor):
        cut = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
        with self.write() as c:
            c.exec_driver_sql(
                "DELETE FROM jobs WHERE updated_at<? AND state NOT IN ('processing','pending')", (cut,)
            )
            c.exec_driver_sql("DELETE FROM audit WHERE occurred_at<?", (cut,))
            self.audit(c, actor.subject, "retention_applied", None)
