from contextlib import suppress
from pathlib import Path
from time import perf_counter
from typing import Annotated, Literal
from uuid import UUID
import asyncio

from pydantic import Field, StringConstraints

from . import analysis
from .retrieval import Retrieval
from .runtime import LocalTransformer, Ollama, RuntimeFailure
from .schemas import Analysis, Input
from .settings import Settings
from .store import Store, checksum


class Case(Input):
    id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,48}$")]
    request: Analysis
    expected: Literal["grounded", "abstain"]
    references: list[UUID] = Field(default_factory=list, max_length=6)
    terms: list[Annotated[str, StringConstraints(min_length=2, max_length=48)]] = Field(
        default_factory=list, max_length=8
    )


class Suite(Input):
    cases: list[Case] = Field(min_length=1, max_length=20)


async def compare(suite: Suite, model_ids: list[str], store: Store, runtime: Ollama, settings: Settings, internal=False):
    if not 1 <= len(model_ids) <= 4 or len(set(model_ids)) != len(model_ids):
        raise ValueError("Gunakan 1–4 model inference berbeda yang telah disetujui.")
    if len({case.id for case in suite.cases}) != len(suite.cases):
        raise ValueError("ID kasus evaluasi harus unik.")
    models = []
    for identifier in model_ids:
        model = store.one(
            "SELECT * FROM models WHERE id=? AND enabled=1 AND role='inference'", (UUID(identifier).hex,)
        )
        if not model:
            raise ValueError("Model evaluasi belum disetujui atau dinonaktifkan.")
        models.append(model)
    transformer = (
        LocalTransformer(settings.local_embedding_dir, settings.local_embedding_sha256)
        if settings.local_embedding_dir else None
    )
    retrieval = Retrieval(store, runtime, transformer)
    results = []
    for case in suite.cases:
        data = case.request.model_dump(mode="json")
        expected = {identifier.hex for identifier in case.references}
        started = perf_counter()
        candidates, _ = await retrieval.search(analysis.normalize_query(data, internal), semantic=False)
        observed = {entry["document_id"] for entry in candidates}
        baseline = {
            "elapsed_ms": round(1000 * (perf_counter() - started), 2),
            "support_found": bool(observed),
            "expected_retrieved": len(expected & observed),
            "expected_total": len(expected),
            "retrieved_total": len(observed),
            "precision": round(len(expected & observed) / len(observed), 4) if expected and observed else None,
            "recall": round(len(expected & observed) / len(expected), 4) if expected else None,
        }
        comparisons = []
        for model in models:
            started = perf_counter()
            result = {"name": model["name"], "digest": model["digest"]}
            try:
                answer, metrics, _ = await asyncio.wait_for(
                    analysis.analyze("evaluation", data, internal, retrieval, runtime, settings, model=model),
                    settings.timeout,
                )
                abstained = answer["status"] == "insufficient_evidence"
                citations = {entry["document_id"] for entry in answer["source_references"]}
                text = (answer["summary"] + " " + " ".join(entry["text"] for entry in answer["recommendations"])).casefold()
                result.update(
                    outcome="abstain" if abstained else "grounded",
                    matches_expectation=abstained == (case.expected == "abstain"),
                    expected_cited=len(expected & citations), expected_total=len(expected), citations=len(citations),
                    citation_precision=round(len(expected & citations) / len(citations), 4) if expected and citations else None,
                    citation_recall=round(len(expected & citations) / len(expected), 4) if expected else None,
                    terms_matched=sum(term.casefold() in text for term in case.terms),
                    terms_total=len(case.terms), retrieval=answer["retrieval"]["method"], metrics=metrics,
                )
            except (RuntimeFailure, TimeoutError) as error:
                result.update(outcome="failed", error=getattr(error, "code", "worker_timeout"))
            result["elapsed_ms"] = round(1000 * (perf_counter() - started), 2)
            comparisons.append(result)
        results.append({"case": case.id, "expected": case.expected, "keyword_baseline": baseline, "models": comparisons})
    return {"suite_sha256": checksum(suite.model_dump_json()), "internal": internal, "cases": results}


async def run(path: Path, models: list[str], internal: bool):
    with path.open("rb") as file:
        content = file.read(128 * 1024 + 1)
    if len(content) > 128 * 1024:
        raise ValueError("Suite evaluasi melebihi 128 KiB.")
    suite = Suite.model_validate_json(content)
    settings = Settings.from_env()
    store = Store(settings.database)
    runtime = Ollama(settings)
    try:
        return await compare(suite, models, store, runtime, settings, internal)
    finally:
        with suppress(Exception):
            await runtime.close()
        store.engine.dispose()
