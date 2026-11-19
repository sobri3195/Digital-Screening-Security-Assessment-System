from contextlib import asynccontextmanager
import asyncio
import json
import platform
import re
import shutil
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, Query as ApiQuery, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
import psutil
from pydantic import Field

from . import analysis
from .retrieval import Query, Retrieval
from .runtime import LocalTransformer, Ollama, RuntimeFailure
from .schemas import (
    Analysis,
    Approval,
    Document,
    Input,
    ModelApproval,
    ModelOptions,
    Review,
    SCOPE,
    Topic,
    TRUSTED_SOURCES,
)
from .security import AccessError, Actor, Authentication
from .settings import Settings
from .store import Store
from .worker import Worker


ROOT = "/api/v1/ai"
CAP = 210000


class BoundRequests:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        body = bytearray()
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > CAP:
                await JSONResponse({"error": "payload_too_large"}, status_code=413)(scope, receive, send)
                return
            more = message.get("more_body", False)
        headers = dict(scope["headers"])
        media = headers.get(b"content-type", b"").split(b";", 1)[0].lower()
        if body and media != b"application/json":
            await JSONResponse({"error": "invalid_content_type"}, status_code=415)(scope, receive, send)
            return
        done = False

        async def replay():
            nonlocal done
            if not done:
                done = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class Activation(Input):
    active: bool


class EmbeddingApproval(Approval):
    embed: bool = False


class SourceApproval(Input):
    enabled: bool


class Retention(Input):
    days: Annotated[int, Field(ge=7, le=3650)]


def get_hardware(path) -> dict:
    ram = psutil.virtual_memory()
    cpu = platform.processor()
    if not cpu and platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as info:
                cpu = next(
                    (
                        line.split(":", 1)[1].strip()
                        for line in info
                        if line.startswith("model name") and ":" in line
                    ),
                    "",
                )
        except OSError:
            pass
    return {
        "cpu": cpu[:160] or platform.machine(),
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(),
        "ram_bytes": ram.total,
        "available_ram_bytes": ram.available,
        "disk_available_bytes": shutil.disk_usage(path.parent).free,
        "platform": platform.system(),
        "gpu_model": None,
        "guidance": "Jalankan benchmark pada model yang telah disetujui untuk menentukan kapasitas.",
    }


def create_app(settings: Settings | None = None, runtime=None) -> FastAPI:
    settings = settings or Settings.from_env()
    auth = Authentication(settings)
    store = Store(settings.database)
    ollama = runtime or Ollama(settings)
    transformer = (
        LocalTransformer(settings.local_embedding_dir, settings.local_embedding_sha256)
        if settings.local_embedding_dir
        else None
    )
    retrieval = Retrieval(store, ollama, transformer)
    worker = Worker(store, ollama, retrieval, settings)

    @asynccontextmanager
    async def life(_):
        runners = (
            [asyncio.create_task(worker.loop()) for _ in range(settings.concurrency)]
            if settings.worker_enabled
            else []
        )
        try:
            yield
        finally:
            for runner in runners:
                runner.cancel()
            await asyncio.gather(*runners, return_exceptions=True)
            await ollama.close()
            store.engine.dispose()

    app = FastAPI(
        title="SENTINEL AI Engine",
        version="3.0.0",
        lifespan=life,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(BoundRequests)
    app.state.store = store
    app.state.worker = worker
    app.state.retrieval = retrieval

    @app.exception_handler(AccessError)
    async def access_error(_, error):
        extra = {"WWW-Authenticate": "Bearer"} if error.status == 401 else {}
        return JSONResponse({"error": error.code}, status_code=error.status, headers=extra)

    @app.exception_handler(RequestValidationError)
    async def invalid_input(_request, error):
        return JSONResponse({"error": "invalid_input"}, status_code=422)

    @app.exception_handler(RuntimeFailure)
    async def failed_runtime(_request, error):
        return JSONResponse({"error": error.code}, status_code=503)

    @app.middleware("http")
    async def no_cache(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def actor(authorization: Annotated[str | None, Header()] = None):
        principal = auth.authenticate(authorization)
        store.rate(principal)
        return principal

    Auth = Depends(actor)

    async def runtime_status():
        try:
            data = await asyncio.wait_for(ollama.tags(), timeout=4)
        except (RuntimeFailure, asyncio.TimeoutError):
            return "unavailable", []
        return "connected", data

    @app.get(ROOT + "/health")
    async def health(user: Actor = Auth):
        user.require("ai.dashboard.view")
        connectivity, tags = await runtime_status()
        model = store.active("inference")
        available = bool(
            model and any(x["name"] == model["name"] and x["digest"] == model["digest"] for x in tags)
        )
        return {
            "status": "ready"
            if available
            else "not_configured"
            if connectivity == "connected"
            else "unavailable",
            "runtime": connectivity,
            "active_model": model["name"] if model else None,
            "model_available": available,
        }

    @app.get(ROOT + "/status")
    async def status(user: Actor = Auth):
        user.require("ai.dashboard.view")
        active = store.active("inference")
        counts = store.rows("SELECT state,COUNT(*) AS count FROM jobs GROUP BY state")
        samples = store.rows("""SELECT kind, COUNT(*) AS total FROM jobs GROUP BY kind ORDER BY total DESC""")
        recent = store.rows("""SELECT substr(created_at,1,10) AS day,COUNT(*) AS total,
            SUM(CASE WHEN state='failed' THEN 1 ELSE 0 END) AS failed FROM jobs GROUP BY day ORDER BY day DESC LIMIT 14""")
        times = store.one("""SELECT AVG(json_extract(metrics,'$.elapsed_ms')) AS avg_ms,
            SUM(json_extract(metrics,'$.output_tokens')) AS tokens,MAX(json_extract(metrics,'$.runtime_vram_bytes')) AS last_observed_vram_bound
            FROM jobs WHERE metrics IS NOT NULL""")
        knowledge = store.one("""SELECT count(*) AS documents,MAX(d.published) AS latest_publication
            FROM documents d JOIN sources s ON s.code=d.source_code WHERE d.state='approved' AND s.enabled=1""")
        return {
            "jobs": counts,
            "analysis_types": samples,
            "daily": recent,
            "performance": times,
            "active_model": active["name"] if active else None,
            "knowledge": knowledge,
            "hardware": get_hardware(store.path),
            "anomaly": analysis.anomaly([row["failed"] for row in reversed(recent)]),
        }

    @app.get(ROOT + "/models")
    async def models(user: Actor = Auth):
        user.require("ai.dashboard.view")
        connectivity, tags = await runtime_status()
        approved = store.rows(
            """SELECT id,name,digest,role,license_reference,options,approved_at,enabled,active FROM models ORDER BY approved_at DESC LIMIT 150"""
        )
        for item in approved:
            item["options"] = json.loads(item["options"])
            item["available"] = any(
                entry["name"] == item["name"] and entry["digest"] == item["digest"] for entry in tags
            )
        return {"runtime": connectivity, "installed": tags, "approved": approved}

    @app.post(ROOT + "/models", status_code=201)
    async def model_approval(body: ModelApproval, user: Actor = Auth):
        user.require("ai.model.manage")
        try:
            selected = next(
                (x for x in await asyncio.wait_for(ollama.tags(), timeout=5) if x["name"] == body.name), None
            )
        except asyncio.TimeoutError:
            raise AccessError(503, "runtime_unavailable") from None
        if not selected:
            raise AccessError(404, "model_not_installed")
        try:
            await asyncio.wait_for(ollama.ensure_model(selected), timeout=5)
        except asyncio.TimeoutError:
            raise AccessError(503, "runtime_unavailable") from None
        return {
            "id": store.approve_model(user, body.name, body.role, selected["digest"], body.license_reference)
        }

    @app.post(ROOT + "/models/{model}/activation")
    def activate(model: UUID, body: Activation, user: Actor = Auth):
        user.require("ai.model.manage")
        store.select_model(user, model.hex, body.active)
        return {"state": "active" if body.active else "inactive"}

    @app.put(ROOT + "/models/{model}/options")
    def options(model: UUID, body: ModelOptions, user: Actor = Auth):
        user.require("ai.model.manage")
        store.model_options(user, model.hex, body)
        return {"state": "updated"}

    @app.post(ROOT + "/models/{model}/benchmark", status_code=202)
    def model_benchmark(model: UUID, user: Actor = Auth):
        user.require("ai.model.manage")
        return {"id": store.queue(user, "benchmark", {"model_id": model.hex})}

    @app.get(ROOT + "/knowledge/sources")
    def sources(user: Actor = Auth):
        user.require("ai.knowledge.view")
        return store.rows("SELECT * FROM sources ORDER BY title")

    @app.put(ROOT + "/knowledge/sources/{source}")
    def source_options(source: str, request: SourceApproval, user: Actor = Auth):
        user.require("ai.knowledge.manage")
        if source not in TRUSTED_SOURCES:
            raise AccessError(404, "source_not_found")
        store.set_source(source, request.enabled, user)
        return {"enabled": request.enabled}

    @app.get(ROOT + "/knowledge/documents")
    def documents(user: Actor = Auth):
        user.require("ai.knowledge.view")
        managed = "ai.knowledge.manage" in user.scopes or "ai.knowledge.approve" in user.scopes
        return store.rows(
            """SELECT d.id,d.title,d.version,d.state,d.index_status,d.published,d.reference,d.checksum,
            d.classification,s.title AS source,d.source_code,d.updated_at
            FROM documents d JOIN sources s ON s.code=d.source_code WHERE ?=1 OR (d.state='approved' AND s.enabled=1)
            ORDER BY d.updated_at DESC LIMIT 100""",
            (int(managed),),
        )

    @app.post(ROOT + "/knowledge/documents", status_code=201)
    def submit_document(document: Document, user: Actor = Auth):
        user.require("ai.knowledge.manage", "ai.knowledge.view")
        return {"id": store.create_document(document, user), "state": "draft"}

    @app.get(ROOT + "/knowledge/documents/{doc}")
    def document_detail(doc: UUID, user: Actor = Auth):
        user.require("ai.knowledge.view")
        reviewer = "ai.knowledge.approve" in user.scopes
        row = store.one(
            """SELECT d.id,d.title,d.version,d.state,d.index_status,d.published,d.reference,d.checksum,d.content,d.facts,
            d.classification,s.title AS source,d.updated_at FROM documents d JOIN sources s ON s.code=d.source_code
            WHERE d.id=? AND ((d.state='approved' AND s.enabled=1) OR d.submitted_by=? OR ?=1)""",
            (doc.hex, user.subject, int(reviewer)),
        )
        if not row:
            raise AccessError(404, "document_not_found")
        row["facts"] = json.loads(row["facts"])
        return row

    @app.post(ROOT + "/knowledge/documents/{doc}/approve")
    def approve_document(doc: UUID, body: EmbeddingApproval, user: Actor = Auth):
        user.require("ai.knowledge.approve")
        return {"state": "approved", "index_job": store.approve_document(doc.hex, user, body.embed)}

    @app.post(ROOT + "/knowledge/documents/{doc}/archive")
    def archive_document(doc: UUID, user: Actor = Auth):
        user.require("ai.knowledge.approve")
        store.archive_document(doc.hex, user)
        return {"state": "archived"}

    @app.post(ROOT + "/knowledge/documents/{doc}/index", status_code=202)
    def index_document(doc: UUID, user: Actor = Auth):
        user.require("ai.knowledge.manage", "ai.knowledge.approve")
        return {"id": store.queue(user, "index", {"document_id": doc.hex})}

    @app.get(ROOT + "/knowledge/search")
    async def search(
        q: Annotated[str, ApiQuery(min_length=2, max_length=200)],
        user: Actor = Auth,
        topic: Topic | None = None,
        source: Annotated[str | None, ApiQuery(max_length=16)] = None,
    ):
        user.require("ai.knowledge.view")
        if not re.fullmatch(r"[A-Za-z0-9 .:/_-]+", q):
            raise AccessError(422, "invalid_search")
        if source and source not in TRUSTED_SOURCES:
            raise AccessError(422, "invalid_search")
        try:
            rows, meta = await asyncio.wait_for(
                retrieval.search(Query(q, topic=topic, source=source, internal=True)), timeout=8
            )
        except asyncio.TimeoutError:
            raise AccessError(504, "search_timeout") from None
        return {"documents": rows, "retrieval": meta}

    def submit(body, user):
        user.require("ai.analysis.execute", SCOPE[body.kind])
        # Counts are accepted only from the delegated web backend, which derives them from SQL.
        if body.kind in ("report", "executive") and not user.subject.startswith("web:"):
            raise AccessError(403, "aggregates_require_web")
        data = body.model_dump(mode="json") | {"_allow_internal": "ai.knowledge.view" in user.scopes}
        return {"id": store.queue(user, body.kind, data)}

    @app.post(ROOT + "/analyze/{kind}", status_code=202)
    def submit_analysis(kind: str, body: Analysis, user: Actor = Auth):
        if kind != body.kind or kind in ("report", "executive"):
            raise AccessError(422, "analysis_type_mismatch")
        return submit(body, user)

    @app.post(ROOT + "/reports/{action}", status_code=202)
    def submit_report(action: str, body: Analysis, user: Actor = Auth):
        expected = {"summary": "executive", "generate": "report"}
        if expected.get(action) != body.kind:
            raise AccessError(422, "analysis_type_mismatch")
        return submit(body, user)

    @app.get(ROOT + "/tasks")
    def tasks(user: Actor = Auth, offset: Annotated[int, ApiQuery(ge=0, le=10000)] = 0):
        if not user.scopes.intersection(
            {
                "ai.analysis.execute",
                "ai.report.review",
                "ai.model.manage",
                "ai.knowledge.manage",
                "ai.knowledge.approve",
                "ai.evaluation.execute",
            }
        ):
            raise AccessError(403, "insufficient_scope")
        rows = store.rows(
            """SELECT id,kind,state,created_at,updated_at,model_name,error_code FROM jobs
            WHERE owner=? OR (?=1 AND kind NOT IN ('index','benchmark','evaluate'))
            ORDER BY created_at DESC LIMIT 40 OFFSET ?""",
            (user.subject, int("ai.report.review" in user.scopes), offset),
        )
        return {"items": rows, "next_offset": offset + 40 if len(rows) == 40 else None}

    @app.get(ROOT + "/tasks/{task}")
    def task_detail(task: UUID, user: Actor = Auth):
        return store.visible_job(user, task.hex)

    @app.get(ROOT + "/tasks/{task}/events")
    async def events(task: UUID, user: Actor = Auth):
        row = store.visible_job(user, task.hex)

        async def stream():
            nonlocal row
            last = None
            for _ in range(15):
                if row["state"] != last:
                    last = row["state"]
                    yield "event: state\ndata: " + json.dumps({"id": row["id"], "state": last}) + "\n\n"
                if last not in ("pending", "processing"):
                    return
                await asyncio.sleep(1)
                try:
                    row = store.visible_job(user, task.hex)
                except AccessError:
                    return

        return StreamingResponse(
            stream(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )

    @app.post(ROOT + "/tasks/{task}/cancel")
    def cancel(task: UUID, user: Actor = Auth):
        store.cancel(user, task.hex)
        return {"status": "cancel_requested"}

    @app.post(ROOT + "/tasks/{task}/review")
    def review(task: UUID, body: Review, user: Actor = Auth):
        user.require("ai.report.review")
        store.review(user, task.hex, body.decision)
        return {"status": body.decision}

    @app.get(ROOT + "/evaluation")
    def evaluation(user: Actor = Auth):
        user.require("ai.evaluation.execute")
        return [
            {
                "id": row["id"],
                "state": row["state"],
                "result": json.loads(row["result"]) if row["result"] else None,
                "created_at": row["created_at"],
            }
            for row in store.rows(
                "SELECT id,state,result,created_at FROM jobs WHERE kind='evaluate' AND owner=? ORDER BY created_at DESC LIMIT 30",
                (user.subject,),
            )
        ]

    @app.post(ROOT + "/evaluation", status_code=202)
    def run_evaluation(user: Actor = Auth):
        user.require("ai.evaluation.execute")
        return {"id": store.queue(user, "evaluate", {})}

    @app.get(ROOT + "/templates")
    def templates(user: Actor = Auth):
        user.require("ai.template.manage")
        return {
            "version": analysis.TEMPLATE,
            "analysis_types": list(SCOPE),
            "approval": "bundled_code_review",
            "plan_schema": analysis.Plan.model_json_schema(),
        }

    @app.get(ROOT + "/audit")
    def audit(user: Actor = Auth):
        user.require("ai.audit.view")
        return store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 100")

    @app.post(ROOT + "/settings/retention")
    def retention(body: Retention, user: Actor = Auth):
        user.require("ai.settings.manage")
        store.purge(body.days, user)
        return {"status": "retention_applied"}

    return app
