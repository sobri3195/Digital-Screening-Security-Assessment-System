import asyncio
import json
import logging

from . import analysis
from .retrieval import Retrieval
from .runtime import Ollama, RuntimeFailure
from .settings import Settings
from .store import Store


LOG = logging.getLogger("sentinel_ai.worker")
EVALUATION_CASES = (
    ("CVE-2021-44228", "known"),
    ("CVE-9999-999999999", "absent"),
)


class Worker:
    def __init__(self, store: Store, runtime: Ollama, retrieval: Retrieval, settings: Settings):
        self.store = store
        self.runtime = runtime
        self.retrieval = retrieval
        self.settings = settings

    async def _run(self, job):
        data = json.loads(job["payload"])
        if job["kind"] == "index":
            return await self.retrieval.index_document(data["document_id"]), None, None, "completed"
        if job["kind"] == "benchmark":
            result, metrics, model = await analysis.benchmark(
                self.retrieval, self.runtime, data.get("model_id")
            )
            return result, metrics, model, "completed"
        if job["kind"] == "evaluate":
            decisions = []
            for cve, expected in EVALUATION_CASES:
                query = analysis.normalize_query({"kind": "vulnerability", "cve": cve}, False)
                rows, meta = await self.retrieval.search(query, semantic=False)
                exact = all(row["facts"].get("cve") == cve for row in rows)
                decisions.append(
                    {
                        "cve": cve,
                        "expected": expected,
                        "evidence_count": len(rows),
                        "exact": exact,
                        "passed": bool(rows) == (expected == "known") and exact,
                        "method": meta["method"],
                    }
                )
            return (
                {
                    "method": "keyword_retrieval_measured",
                    "cases": decisions,
                    "passed": sum(item["passed"] for item in decisions),
                    "total": len(decisions),
                },
                None,
                None,
                "completed",
            )
        internal = bool(data.pop("_allow_internal", False))
        template = data.pop("_template", None)
        result, metrics, model = await analysis.analyze(
            job["id"], data, internal, self.retrieval, self.runtime, self.settings, template=template,
        )
        return result, metrics, model, "requires_review"

    async def run_once(self) -> bool:
        job = self.store.claim(self.settings.timeout, self.settings.concurrency)
        if job is None:
            return False
        task = asyncio.create_task(self._run(job))
        started = asyncio.get_running_loop().time()
        try:
            while not task.done():
                await asyncio.wait([task], timeout=0.25)
                if self.store.cancelled(job):
                    task.cancel()
                    await discard(task)
                    self.store.complete(job, "cancelled")
                    return True
                if asyncio.get_running_loop().time() - started > self.settings.timeout:
                    task.cancel()
                    await discard(task)
                    raise RuntimeFailure("worker_timeout", True)
            result, metrics, model, state = await task
            self.store.complete(job, state, result=result, metrics=metrics, model=model)
        except RuntimeFailure as error:
            self.store.complete(job, "failed", error=error.code, retry=error.retry)
        except asyncio.CancelledError:
            task.cancel()
            await discard(task)
            self.store.complete(job, "failed", error="worker_interrupted", retry=True)
            raise
        except Exception as error:
            LOG.warning("Job failure: %s", type(error).__name__)
            self.store.complete(job, "failed", error="worker_error")
        return True

    async def loop(self):
        while True:
            try:
                worked = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as error:
                LOG.warning("Worker polling failure: %s", type(error).__name__)
                worked = False
            if not worked:
                await asyncio.sleep(0.8)


async def discard(task):
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass
