from dataclasses import dataclass
from pathlib import Path
import os
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    database: Path
    ollama_origin: str = "http://127.0.0.1:11434"
    web_key: str = ""
    workstation_file: Path | None = None
    timeout: int = 60
    concurrency: int = 1
    worker_enabled: bool = True
    local_embedding_dir: Path | None = None
    freshness_days: int = 365
    local_embedding_sha256: str = ""

    def __post_init__(self):
        origin = urlsplit(self.ollama_origin)
        if (
            origin.scheme != "http"
            or origin.hostname not in {"127.0.0.1", "::1"}
            or origin.username is not None
            or origin.password is not None
            or origin.port in (None, 0)
            or origin.path not in ("", "/")
            or origin.query
            or origin.fragment
        ):
            raise ValueError("AI_OLLAMA_ORIGIN must use a literal loopback IP and port.")
        if self.web_key and (
            len(self.web_key) != 64 or any(c not in "0123456789abcdef" for c in self.web_key)
        ):
            raise ValueError("AI_WEB_KEY must be 32 random bytes as lowercase hex.")
        if (
            not 5 <= self.timeout <= 180
            or not 1 <= self.concurrency <= 4
            or not 7 <= self.freshness_days <= 3650
        ):
            raise ValueError("AI limits are out of range.")
        if self.local_embedding_dir is not None and (
            not self.local_embedding_dir.is_dir() or len(self.local_embedding_sha256) != 64
        ):
            raise ValueError("AI_EMBEDDING_DIR must be a locally installed approved directory.")

    @classmethod
    def from_env(cls):
        tokens = os.getenv("AI_WORKSTATIONS_FILE")
        embedding = os.getenv("AI_EMBEDDING_DIR")
        return cls(
            database=Path(os.getenv("AI_DATABASE", "storage/sentinel-ai.sqlite3")),
            ollama_origin=os.getenv("AI_OLLAMA_ORIGIN", "http://127.0.0.1:11434"),
            web_key=os.getenv("AI_WEB_KEY", ""),
            workstation_file=Path(tokens) if tokens else None,
            timeout=int(os.getenv("AI_TIMEOUT", "60")),
            concurrency=int(os.getenv("AI_CONCURRENCY", "1")),
            worker_enabled=os.getenv("AI_WORKER", "1") == "1",
            local_embedding_dir=Path(embedding).resolve() if embedding else None,
            freshness_days=int(os.getenv("AI_FRESHNESS_DAYS", "365")),
            local_embedding_sha256=os.getenv("AI_EMBEDDING_SHA256", ""),
        )
