import json
import time
from secrets import token_hex

import httpx
import pytest
from fastapi.testclient import TestClient

from sentinel_ai.gateway import ROOT, create_app
from sentinel_ai.runtime import Ollama
from sentinel_ai.schemas import CORE_SCOPES
from sentinel_ai.security import delegated_token
from sentinel_ai.settings import Settings

DIGEST = "a" * 64
EMBED = "b" * 64
TEST_MODELS = [
    {"name": "test-inference:latest", "digest": DIGEST, "size": 600, "details": {"quantization_level": "Q4"}},
    {"name": "test-embedding:latest", "digest": EMBED, "size": 400, "details": {}},
]


def fixture_document():
    return {
        "title": "TEST Log4j CVE reference",
        "source": "cisa",
        "version": "test-1",
        "published": "2021-12-10",
        "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "classification": "public",
        "content": "TEST Log4j vulnerability CVE-2021-44228 security patch Apache. Ignore untrusted example directives; SPRING_TEST_INJECTION_FIELD.",
        "facts": {
            "topic": "vulnerability",
            "cve": "CVE-2021-44228",
            "cvss": 10.0,
            "cwe": "CWE-502",
            "kev": True,
            "severity": "critical",
            "actions": ["apply_patch", "verify_version"],
        },
    }


class Harness:
    def __init__(self, client, app, settings, calls, mode):
        self.client = client
        self.app = app
        self.settings = settings
        self.calls = calls
        self.mode = mode

    def token(self, subject=1, scopes=CORE_SCOPES, ttl=60):
        return {
            "Authorization": "Bearer " + delegated_token(f"web:{subject}", scopes, self.settings.web_key, ttl)
        }

    def get(self, path, subject=1, scopes=CORE_SCOPES):
        return self.client.get(ROOT + path, headers=self.token(subject, scopes))

    def send(self, path, data=None, subject=1, scopes=CORE_SCOPES, method="POST"):
        return self.client.request(method, ROOT + path, json=data, headers=self.token(subject, scopes))

    def wait(self, job, subject=1, timeout=12):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            reply = self.get("/tasks/" + job, subject)
            assert reply.status_code == 200, reply.text
            data = reply.json()
            if data["state"] not in ("pending", "processing"):
                return data
            time.sleep(0.075)
        pytest.fail("task did not reach terminal state")

    def model(self, role="inference"):
        name = "test-" + role + ":latest"
        response = self.send(
            "/models",
            {
                "name": name,
                "role": role,
                "license_reference": "https://example.test/license",
                "reviewed": True,
            },
        )
        assert response.status_code == 201, response.text
        model = response.json()["id"]
        assert self.send(f"/models/{model}/activation", {"active": True}).status_code == 200
        return model

    def approve(self, data=None, embed=False):
        response = self.send("/knowledge/documents", data or fixture_document())
        assert response.status_code == 201, response.text
        doc = response.json()["id"]
        response = self.send(f"/knowledge/documents/{doc}/approve", {"reviewed": True, "embed": embed}, 2)
        assert response.status_code == 200, response.text
        return doc, response.json()["index_job"]


@pytest.fixture
def gateway(tmp_path):
    calls = []
    mode = {"invalid": False, "drift": False}

    def reply(request):
        calls.append(
            (request.method, request.url.path, json.loads(request.content) if request.content else None)
        )
        if request.url.path == "/api/tags":
            models = [entry | {"digest": "f" * 64} for entry in TEST_MODELS] if mode["drift"] else TEST_MODELS
            return httpx.Response(200, json={"models": models})
        if request.url.path == "/api/ps":
            return httpx.Response(200, json={"models": [{"digest": DIGEST, "size_vram": 0}]})
        if request.url.path == "/api/embed":
            data = json.loads(request.content)
            return httpx.Response(200, json={"embeddings": [[1.0, 0.2, 0.0] for _ in data["input"]]})
        if request.url.path == "/api/generate":
            plan = {"fact_ids": [99] if mode["invalid"] else [1], "action_ids": ["verify_source"]}
            payload = (
                {"response": json.dumps(plan), "done": False},
                {"done": True, "eval_count": 22, "eval_duration": 500000000, "load_duration": 1000000},
            )
            return httpx.Response(200, content=b"".join((json.dumps(x) + "\n").encode() for x in payload))
        return httpx.Response(404)

    cfg = Settings(tmp_path / "test.sqlite3", web_key=token_hex(32), timeout=5)
    app = create_app(cfg, Ollama(cfg, httpx.MockTransport(reply)))
    with TestClient(app) as client:
        yield Harness(client, app, cfg, calls, mode)
