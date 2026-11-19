from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import re
import time

from .schemas import CORE_SCOPES
from .settings import Settings


class AccessError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code


@dataclass(frozen=True)
class Actor:
    subject: str
    scopes: frozenset[str]

    def require(self, *scopes: str):
        if not self.scopes.issuperset(scopes):
            raise AccessError(403, "insufficient_scope")


def encoded(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def delegated_token(subject: str, scopes, secret: str, ttl: int = 60) -> str:
    data = encoded(
        json.dumps(
            {"sub": subject, "aud": "sentinel-ai", "exp": int(time.time()) + ttl, "scopes": sorted(scopes)},
            separators=(",", ":"),
        ).encode()
    )
    sign = encoded(hmac.digest(bytes.fromhex(secret), ("v1." + data).encode(), "sha256"))
    return "v1." + data + "." + sign


class Authentication:
    def __init__(self, settings: Settings):
        self.web_key = settings.web_key
        self.credentials = {}
        if settings.workstation_file:
            with settings.workstation_file.open("rb") as handle:
                raw = handle.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024:
                raise ValueError("Workstation registry too large")
            listing = json.loads(raw)
            if not isinstance(listing, list) or len(listing) > 500:
                raise ValueError("Invalid workstation registry")
            for item in listing:
                if not isinstance(item, dict) or set(item) != {"id", "sha256", "scopes"}:
                    raise ValueError("Invalid workstation entry")
                name, key, scopes = item["id"], item["sha256"], item["scopes"]
                if (
                    not isinstance(key, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", key)
                    or key in self.credentials
                    or not isinstance(name, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", name)
                    or not isinstance(scopes, list)
                    or not all(isinstance(s, str) and s in CORE_SCOPES for s in scopes)
                ):
                    raise ValueError("Invalid workstation entry")
                self.credentials[key] = Actor("workstation:" + name, frozenset(scopes))

    def authenticate(self, authorization: str | None) -> Actor:
        if not authorization or len(authorization) > 4096 or not authorization.startswith("Bearer "):
            raise AccessError(401, "authentication_required")
        token = authorization[7:]
        if token.startswith("v1.") and self.web_key:
            try:
                part, data, signature = token.split(".")
                if not re.fullmatch(r"[A-Za-z0-9_-]+", data) or not re.fullmatch(
                    r"[A-Za-z0-9_-]{43}", signature
                ):
                    raise ValueError
                verify = hmac.digest(bytes.fromhex(self.web_key), (part + "." + data).encode(), "sha256")
                if not hmac.compare_digest(encoded(verify), signature):
                    raise ValueError
                claims = json.loads(_decode(data))
                if not isinstance(claims, dict) or set(claims) != {"aud", "exp", "sub", "scopes"}:
                    raise ValueError
                now = int(time.time())
                if (
                    claims["aud"] != "sentinel-ai"
                    or type(claims["exp"]) is not int
                    or not now < claims["exp"] <= now + 120
                    or not isinstance(claims["sub"], str)
                    or not re.fullmatch(r"(?:web|client):[1-9][0-9]{0,19}", claims["sub"])
                    or not isinstance(claims["scopes"], list)
                    or not all(isinstance(s, str) and s in CORE_SCOPES for s in claims["scopes"])
                ):
                    raise ValueError
                return Actor(claims["sub"], frozenset(claims["scopes"]))
            except (ValueError, TypeError, KeyError, UnicodeError):
                raise AccessError(401, "invalid_token") from None
        if re.fullmatch(r"[a-f0-9]{64}", token):
            hashed = sha256(token.encode()).hexdigest()
            # Compare all configured hashes; registry size is bounded on load.
            for known, actor in self.credentials.items():
                if hmac.compare_digest(known, hashed):
                    return actor
        raise AccessError(401, "invalid_token")
