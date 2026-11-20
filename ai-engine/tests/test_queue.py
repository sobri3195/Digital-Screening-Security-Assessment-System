from hashlib import sha256
import json
from secrets import token_hex

from fastapi.testclient import TestClient

from sentinel_ai.gateway import ROOT, create_app
from sentinel_ai.schemas import CORE_SCOPES
from sentinel_ai.security import delegated_token
from sentinel_ai.settings import Settings
from conftest import fixture_document


def test_dedup_cancellation_and_workstation_permissions(tmp_path):
    secret = token_hex(32)
    registry = tmp_path / "tokens.json"
    registry.write_text(
        json.dumps(
            [
                {
                    "id": "TEST-LAB",
                    "sha256": sha256(secret.encode()).hexdigest(),
                    "scopes": ["ai.dashboard.view"],
                }
            ]
        )

    )
    settings = Settings(
        tmp_path / "ai.sqlite3", web_key=token_hex(32), workstation_file=registry, worker_enabled=False
    )
    with TestClient(create_app(settings)) as client:
        owner = {"Authorization": "Bearer " + delegated_token("web:1", CORE_SCOPES, settings.web_key)}
        viewer = {
            "Authorization": "Bearer " + delegated_token("web:2", {"ai.analysis.execute"}, settings.web_key)
        }
        workstation = {"Authorization": "Bearer " + secret}
        request = {"kind": "vulnerability", "cve": "CVE-2021-44228"}
        first = client.post(ROOT + "/analyze/vulnerability", json=request, headers=owner).json()["id"]
        second = client.post(ROOT + "/analyze/vulnerability", json=request, headers=owner).json()["id"]
        assert first == second
        assert client.post(ROOT + "/tasks/" + first + "/cancel", headers=viewer).status_code == 404
        assert client.post(ROOT + "/tasks/" + first + "/cancel", headers=owner).status_code == 200
        assert client.get(ROOT + "/tasks/" + first, headers=owner).json()["state"] == "cancelled"
        assert "event: state" in client.get(ROOT + "/tasks/" + first + "/events", headers=owner).text
        assert client.get(ROOT + "/health", headers=workstation).status_code == 200
        assert (
            client.post(ROOT + "/analyze/vulnerability", json=request, headers=workstation).status_code == 403
        )


def test_approval_when_embedding_queue_is_full_can_be_retried(tmp_path):
    settings = Settings(tmp_path / "ai.sqlite3", web_key=token_hex(32), worker_enabled=False)
    with TestClient(create_app(settings)) as client:
        def headers(actor, scopes=CORE_SCOPES):
            return {"Authorization": "Bearer " + delegated_token(actor, scopes, settings.web_key)}

        reviewer = headers("web:2", {"ai.knowledge.view", "ai.knowledge.approve", "ai.analysis.execute", "ai.vulnerability.analyze"})
        document = client.post(ROOT + "/knowledge/documents", headers=headers("web:1"), json=fixture_document()).json()["id"]
        route = ROOT + "/knowledge/documents/" + document
        jobs = [
            client.post(
                ROOT + "/analyze/vulnerability", headers=reviewer,
                json={"kind":"vulnerability", "cve":f"CVE-2099-{index:04d}"},
            ).json()["id"]
            for index in range(12)
        ]
        approval = client.post(route + "/approve", headers=reviewer, json={"reviewed":True,"embed":True})
        assert approval.status_code == 200
        assert approval.json() == {
            "state":"approved","index_job":None,"index_request":"deferred","index_status":"keyword",
        }
        assert client.post(route + "/index", headers=reviewer).status_code == 429
        client.post(ROOT + "/tasks/" + jobs[0] + "/cancel", headers=reviewer)
        retry = client.post(route + "/index", headers=reviewer)
        assert retry.status_code == 202 and retry.json()["id"]
        assert client.post(route + "/index", headers=reviewer).json() == retry.json()
