import json
import os
from secrets import token_hex
import time

import pytest
from fastapi.testclient import TestClient

from sentinel_ai.gateway import ROOT, create_app
from sentinel_ai.schemas import CORE_SCOPES
from sentinel_ai.security import delegated_token
from sentinel_ai.settings import Settings


@pytest.mark.skipif(
    os.getenv("AI_LIVE_TEST") != "1", reason="Requires explicitly provisioned local Ollama models"
)
def test_real_local_models_retrieval_and_review(tmp_path):
    inference = os.environ["AI_LIVE_INFERENCE_MODEL"]
    embedding = os.environ["AI_LIVE_EMBEDDING_MODEL"]
    config = Settings(
        tmp_path / "live.sqlite3",
        ollama_origin=os.getenv("AI_OLLAMA_ORIGIN", "http://127.0.0.1:11434"),
        web_key=token_hex(32),
        timeout=90,
    )
    with TestClient(create_app(config)) as client:

        def headers(subject):
            return {
                "Authorization": "Bearer " + delegated_token(f"web:{subject}", CORE_SCOPES, config.web_key)
            }

        def call(method, path, data=None, subject=1, expected=200):
            response = client.request(method, ROOT + path, json=data, headers=headers(subject))
            assert response.status_code == expected, response.text
            return response.json()

        def wait(task, subject=1):
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                item = call("GET", "/tasks/" + task, subject=subject)
                if item["state"] not in ("pending", "processing"):
                    return item
                time.sleep(0.5)
            pytest.fail("local Ollama task timed out")

        dataset = {
            "title": "CISA Known Exploited Vulnerabilities – Apache Log4j",
            "source": "cisa",
            "version": "kev-2021-12-10",
            "published": "2021-12-10",
            "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "classification": "public",
            "content": "CISA Known Exploited Vulnerabilities catalog documents Apache Log4j CVE-2021-44228. Consult vendor remediation guidance and update affected versions.",
            "facts": {
                "topic": "vulnerability",
                "cve": "CVE-2021-44228",
                "kev": True,
                "actions": ["apply_patch"],
            },
        }
        model_ids = {}
        for name, role, license in (
            (inference, "inference", "https://ollama.com/library/qwen2.5"),
            (embedding, "embedding", "https://ollama.com/library/nomic-embed-text"),
        ):
            identifier = call(
                "POST",
                "/models",
                {"name": name, "role": role, "license_reference": license, "reviewed": True},
                expected=201,
            )["id"]
            model_ids[role] = identifier
            call("PUT", f"/models/{identifier}/options", {"context": 2048, "device": "cpu"})
            call("POST", f"/models/{identifier}/activation", {"active": True})
        health = call("GET", "/health")
        assert health["status"] == "ready"
        doc = call("POST", "/knowledge/documents", dataset, expected=201)["id"]
        indexed = call(
            "POST", f"/knowledge/documents/{doc}/approve", {"reviewed": True, "embed": True}, subject=2
        )["index_job"]
        index = wait(indexed, 2)
        assert index["state"] == "completed" and index["result"]["indexed_chunks"] >= 1, index
        search = call("GET", "/knowledge/search?q=Apache+Log4j")
        assert search["retrieval"]["method"] == "hybrid", search["retrieval"]
        assert search["documents"][0]["document_id"] == doc
        # Confirm the live worker consumes a task and obtains numeric runtime instrumentation.
        requested = call(
            "POST", "/analyze/vulnerability", {"kind": "vulnerability", "cve": "CVE-2021-44228"}, expected=202
        )["id"]
        task = wait(requested)
        assert task["state"] == "requires_review" and task["result"]["status"] == "draft", task
        assert task["result"]["source_references"][0]["document_id"] == doc
        assert task["metrics"]["output_tokens"] > 0
        assert task["metrics"]["first_token_ms"] is not None
        call("POST", f"/tasks/{requested}/review", {"decision": "verified"}, subject=2)
        assert call("GET", "/tasks/" + requested)["state"] == "completed"
        snapshot = {
            "model": task["model_name"],
            "inference": task["metrics"],
            "retrieval": search["retrieval"],
            "hardware": call("GET", "/status")["hardware"],
        }
        print("LIVE_OLLAMA_METRICS=" + json.dumps(snapshot, sort_keys=True))
        destination = os.getenv("AI_LIVE_METRICS")
        if destination:
            with open(destination, "w", encoding="utf-8") as stream:
                json.dump(snapshot, stream, indent=2)
