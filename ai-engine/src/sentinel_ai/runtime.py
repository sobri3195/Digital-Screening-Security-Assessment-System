import asyncio
from hashlib import sha256
import json
from pathlib import Path
import re
from time import perf_counter


import httpx
import numpy as np

from .schemas import ModelOptions
from .settings import Settings


class RuntimeFailure(Exception):
    def __init__(self, code: str, retry=False):
        super().__init__(code)
        self.code = code
        self.retry = retry


def model_digest(raw) -> str | None:
    if isinstance(raw, str):
        value = raw.removeprefix("sha256:")
        return value if re.fullmatch(r"[a-f0-9]{64}", value) else None
    return None


class Ollama:
    def __init__(self, settings: Settings, transport=None):
        self.settings = settings
        # The literal loopback endpoint is validated by Settings. Bypass proxy forwarding only for this local socket.
        self.client = httpx.AsyncClient(
            base_url=settings.ollama_origin.rstrip("/"),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(settings.timeout, connect=3),
            transport=transport,
        )

    async def close(self):
        await self.client.aclose()

    async def _json(self, method: str, path: str, payload=None, cap=2_000_000):
        try:
            async with self.client.stream(method, path, json=payload) as response:
                if response.status_code >= 500:
                    raise RuntimeFailure("runtime_error", True)
                if response.status_code >= 300:
                    raise RuntimeFailure("runtime_rejected")
                buf = bytearray()
                async for content in response.aiter_bytes(chunk_size=4096):
                    buf.extend(content)
                    if len(buf) > cap:
                        raise RuntimeFailure("runtime_response_limit")
            item = json.loads(buf)
            if not isinstance(item, dict):
                raise RuntimeFailure("runtime_response_invalid")
            return item
        except (httpx.RequestError, asyncio.TimeoutError):
            raise RuntimeFailure("runtime_unavailable", True) from None
        except (ValueError, UnicodeError):
            raise RuntimeFailure("runtime_response_invalid") from None

    async def tags(self) -> list[dict]:
        response = await self._json("GET", "/api/tags")
        result = []
        models = response.get("models")
        if not isinstance(models, list):
            raise RuntimeFailure("runtime_response_invalid")
        for entry in models[:250]:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            digest = model_digest(entry.get("digest"))
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,95}", name)
                or not digest
            ):
                continue
            details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
            result.append(
                {
                    "name": name,
                    "digest": digest,
                    "size": integer(entry.get("size")),
                    "quantization": str(details.get("quantization_level", ""))[:40],
                    "family": str(details.get("family", ""))[:40],
                }
            )
        return result

    async def ensure_model(self, approved: dict):
        if not any(
            model["name"] == approved["name"] and model["digest"] == approved["digest"]
            for model in await self.tags()
        ):
            raise RuntimeFailure("model_digest_unavailable")

    async def generate(self, approved: dict, system: str, context: str, schema: dict) -> tuple[dict, dict]:
        await self.ensure_model(approved)
        model = ModelOptions.model_validate_json(approved["options"])
        options = {
            "num_ctx": model.context,
            "temperature": model.temperature,
            "top_p": model.top_p,
            "num_predict": model.max_output,
        }
        if model.device == "cpu":
            options["num_gpu"] = 0
        request = {
            "model": approved["name"],
            "system": system,
            "prompt": context,
            "format": schema,
            "stream": True,
            "keep_alive": "2m",
            "options": options,
        }
        start = perf_counter()
        pieces = []
        total_bytes = 0
        first_ms = None
        done = None
        buf = bytearray()
        try:
            async with self.client.stream("POST", "/api/generate", json=request) as response:
                if response.status_code >= 500:
                    raise RuntimeFailure("inference_error", True)
                if response.status_code >= 300:
                    raise RuntimeFailure("inference_rejected")
                async for raw in response.aiter_bytes():
                    total_bytes += len(raw)
                    if total_bytes > 256 * 1024:
                        raise RuntimeFailure("inference_response_limit")
                    buf.extend(raw)
                    while b"\n" in buf:
                        line, _, tail = buf.partition(b"\n")
                        buf = bytearray(tail)
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        if not isinstance(data, dict) or "error" in data:
                            raise RuntimeFailure("inference_error")
                        piece = data.get("response")
                        if isinstance(piece, str) and piece:
                            if first_ms is None:
                                first_ms = round((perf_counter() - start) * 1000, 2)
                            pieces.append(piece)
                        if data.get("done") is True:
                            done = data
                            break
                    if done is not None:
                        break
        except httpx.RequestError:
            raise RuntimeFailure("runtime_unavailable", True) from None
        except (ValueError, UnicodeError):
            raise RuntimeFailure("structured_output_invalid") from None
        duration = round((perf_counter() - start) * 1000, 2)
        if done is None:
            raise RuntimeFailure("inference_incomplete", True)
        try:
            payload = json.loads("".join(pieces))
            if not isinstance(payload, dict):
                raise ValueError
        except ValueError:
            raise RuntimeFailure("structured_output_invalid") from None
        await self.ensure_model(approved)
        tokens = integer(done.get("eval_count"))
        eval_ns = integer(done.get("eval_duration"))
        try:
            loaded = await self._json("GET", "/api/ps")
            vram = next(
                (
                    integer(item.get("size_vram"))
                    for item in loaded.get("models", [])
                    if isinstance(item, dict) and model_digest(item.get("digest")) == approved["digest"]
                ),
                None,
            )
        except RuntimeFailure:
            vram = None
        return payload, {
            "elapsed_ms": duration,
            "first_token_ms": first_ms,
            "load_ms": round((integer(done.get("load_duration")) or 0) / 1e6, 2)
            if done.get("load_duration") is not None
            else None,
            "output_tokens": tokens,
            "input_tokens": integer(done.get("prompt_eval_count")),
            "tokens_per_second": round(tokens * 1e9 / eval_ns, 2) if tokens is not None and eval_ns else None,
            "runtime_vram_bytes": vram,
        }

    async def embed(self, approved: dict, texts: list[str]) -> np.ndarray:
        await self.ensure_model(approved)
        model = ModelOptions.model_validate_json(approved["options"])
        options = {"num_ctx": model.context}
        if model.device == "cpu":
            options["num_gpu"] = 0
        item = await self._json(
            "POST",
            "/api/embed",
            {"model": approved["name"], "input": texts, "options": options, "truncate": False},
        )
        matrix = vectors(item.get("embeddings"), len(texts))
        await self.ensure_model(approved)
        return matrix


def integer(value) -> int | None:
    return value if type(value) is int and 0 <= value < 2**63 else None


def vectors(raw, expected: int) -> np.ndarray:
    try:
        matrix = np.asarray(raw, dtype="<f4")
        if (
            matrix.ndim != 2
            or matrix.shape[0] != expected
            or not 1 <= matrix.shape[1] <= 4096
            or not np.isfinite(matrix).all()
        ):
            raise ValueError
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        if not np.isfinite(norms).all() or np.any(norms <= 0):
            raise ValueError
        return np.ascontiguousarray(matrix / norms, dtype="<f4")
    except (TypeError, ValueError, OverflowError):
        raise RuntimeFailure("embedding_response_invalid") from None


class LocalTransformer:
    def __init__(self, root: Path, expected: str):
        self.root = root
        self.digest = directory_digest(root)
        if expected != self.digest:
            raise ValueError("AI_EMBEDDING_SHA256 does not match the approved local files.")
        self._model = None

    async def embed(self, texts: list[str]) -> np.ndarray:
        return await asyncio.to_thread(self.encode, texts)

    def encode(self, texts: list[str]) -> np.ndarray:
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError:
                raise RuntimeFailure("transformer_not_installed") from None
            self._model = SentenceTransformer(
                str(self.root),
                local_files_only=True,
                trust_remote_code=False,
                device="cpu",
                model_kwargs={"use_safetensors": True},
            )
        return vectors(self._model.encode(texts, show_progress_bar=False), len(texts))


def directory_digest(root: Path) -> str:
    if not root.is_dir():
        raise ValueError("Embedding directory must exist.")
    digest = sha256()
    total = 0
    for entry in sorted(root.rglob("*")):
        if entry.is_symlink():
            raise ValueError("Embedding directory cannot contain links.")
        if entry.is_dir():
            continue
        if not entry.is_file():
            raise ValueError("Embedding directory must contain only regular files.")
        size = entry.stat().st_size
        total += size
        if total > 8 * 1024**3:
            raise ValueError("Embedding directory exceeds 8 GiB.")
        digest.update(entry.relative_to(root).as_posix().encode() + b"\0" + str(size).encode() + b"\0")
        with entry.open("rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
    return digest.hexdigest()
