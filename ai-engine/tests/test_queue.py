from hashlib import sha256
import json
from secrets import token_hex

from fastapi.testclient import TestClient

from sentinel_ai.gateway import ROOT, create_app
from sentinel_ai.schemas import CORE_SCOPES
from sentinel_ai.security import delegated_token
from sentinel_ai.settings import Settings


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
