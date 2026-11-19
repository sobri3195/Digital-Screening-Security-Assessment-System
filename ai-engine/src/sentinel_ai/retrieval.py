from dataclasses import dataclass
from datetime import date, timedelta
import json
import re

import faiss
import numpy as np

faiss.omp_set_num_threads(2)

from .runtime import LocalTransformer, Ollama, RuntimeFailure
from .store import Store, utc


@dataclass(frozen=True)
class Query:
    text: str
    topic: str | None = None
    cve: str | None = None
    indicator: str | None = None
    document: str | None = None
    source: str | None = None
    internal: bool = False


class Retrieval:
    def __init__(self, store: Store, runtime: Ollama, transformer: LocalTransformer | None = None):
        self.store = store
        self.runtime = runtime
        self.transformer = transformer

    def embedder(self):
        if self.transformer:
            return self.transformer.digest, self.transformer.embed
        model = self.store.active("embedding")
        return (model["digest"], lambda data: self.runtime.embed(model, data)) if model else None

    @staticmethod
    def _filters(query: Query):
        where = ["d.state='approved'", "s.enabled=1"]
        args = []
        if not query.internal:
            where.append("d.classification='public'")
        for value, column in (
            (query.topic, "json_extract(d.facts,'$.topic')"),
            (query.cve, "json_extract(d.facts,'$.cve')"),
            (query.indicator, "json_extract(d.facts,'$.known_indicator.indicator')"),
            (query.document, "d.id"),
            (query.source, "d.source_code"),
        ):
            if value:
                where.append(column + "=?")
                args.append(value)
        return " AND ".join(where), args

    async def search(self, query: Query, limit=6, semantic=True) -> tuple[list[dict], dict]:
        conditions, args = self._filters(query)
        terms = list(dict.fromkeys(re.findall(r"[A-Za-z0-9_-]{2,70}", query.text.casefold())))[:16]
        phrase = " OR ".join('"' + word + '"' for word in terms)
        joins = "JOIN documents d ON d.id=c.document_id JOIN sources s ON s.code=d.source_code"
        columns = """c.id AS chunk_id,d.id AS document_id,d.title,d.source_code,s.title AS source,d.version,d.published,d.reference,d.checksum,d.facts"""
        lexical = (
            self.store.rows(
                f"""SELECT {columns} FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid {joins}
            WHERE chunks_fts MATCH ? AND {conditions} ORDER BY bm25(chunks_fts),c.id LIMIT 60""",
                (phrase, *args),
            )
            if phrase
            else []
        )
        exact = []
        if query.cve or query.indicator or query.document or query.topic in ("configuration", "education"):
            exact = self.store.rows(
                f"""SELECT {columns} FROM chunks c {joins}
                WHERE {conditions} AND c.position=0 ORDER BY d.updated_at DESC LIMIT 30""",
                args,
            )
        ranked = {}
        meta = {"method": "keyword", "keyword_chunks": len(lexical), "semantic_chunks": 0}
        for source, weight in ((lexical, 1.0), (exact, 1.2)):
            for index, row in enumerate(source, start=1):
                key = row["chunk_id"]
                prior = ranked.get(key, (0.0, row))
                ranked[key] = (prior[0] + weight / (40 + index), row)
        backend = self.embedder() if semantic else None
        if backend and terms:
            digest, embed = backend
            rows = self.store.rows(
                f"""SELECT {columns},e.vector,e.size FROM embeddings e JOIN chunks c ON c.id=e.chunk_id
                {joins} WHERE e.model_digest=? AND {conditions} LIMIT 5000""",
                (digest, *args),
            )
            groups = {}
            for row in rows:
                groups.setdefault(row["size"], []).append(row)
            if groups:
                try:
                    vector = (await embed([query.text[:1200]]))[0]
                except RuntimeFailure as error:
                    meta["embedding_status"] = error.code
                else:
                    available = groups.get(vector.size, [])
                    if available:
                        values = np.ascontiguousarray(
                            np.vstack([np.frombuffer(row["vector"], dtype="<f4") for row in available]),
                            dtype="float32",
                        )
                        index = faiss.IndexFlatIP(vector.size)
                        index.add(values)
                        distances, positions = index.search(vector.reshape(1, -1), min(len(available), 40))
                        semantic_rows = [
                            available[int(i)]
                            for score, i in zip(distances[0], positions[0])
                            if i >= 0 and score >= 0.37
                        ]
                        if semantic_rows:
                            meta["method"] = "hybrid"
                            meta["semantic_chunks"] = len(semantic_rows)
                            for rank, row in enumerate(semantic_rows, start=1):
                                key = row["chunk_id"]
                                row = {k: v for k, v in row.items() if k not in ("vector", "size")}
                                previous = ranked.get(key, (0.0, row))
                                ranked[key] = (previous[0] + 1 / (40 + rank), row)
        unique = {}
        for _score, row in sorted(ranked.values(), key=lambda pair: (-pair[0], pair[1]["chunk_id"])):
            if row["document_id"] not in unique:
                projected = dict(row)
                projected["facts"] = json.loads(projected["facts"])
                unique[row["document_id"]] = projected
            if len(unique) >= limit:
                break
        return list(unique.values()), meta

    async def index_document(self, doc_id: str):
        backend = self.embedder()
        if not backend:
            raise RuntimeFailure("embedding_not_configured")
        digest, embed = backend
        rows = self.store.rows(
            """SELECT c.id,c.body FROM chunks c JOIN documents d ON d.id=c.document_id JOIN sources s ON s.code=d.source_code
            WHERE d.id=? AND d.state='approved' AND s.enabled=1 ORDER BY c.position""",
            (doc_id,),
        )
        if not rows:
            raise RuntimeFailure("document_not_approved")
        count = 0
        for at in range(0, len(rows), 8):
            group = rows[at : at + 8]
            result = await embed([row["body"] for row in group])
            with self.store.write() as conn:
                state = conn.exec_driver_sql("SELECT state FROM documents WHERE id=?", (doc_id,)).scalar()
                if state != "approved":
                    raise RuntimeFailure("document_not_approved")
                for item, vector in zip(group, result):
                    conn.exec_driver_sql(
                        """INSERT INTO embeddings VALUES(?,?,?,?)
                        ON CONFLICT(chunk_id,model_digest) DO UPDATE SET vector=excluded.vector,size=excluded.size""",
                        (item["id"], digest, vector.size, vector.tobytes()),
                    )
                    count += 1
        with self.store.write() as conn:
            conn.exec_driver_sql(
                "UPDATE documents SET index_status='hybrid',updated_at=? WHERE id=? AND state='approved'",
                (utc(), doc_id),
            )
        return {"indexed_chunks": count, "embedding_digest": digest}


def freshness(published: str, days: int) -> bool:
    return date.fromisoformat(published) < date.today() - timedelta(days=days)
