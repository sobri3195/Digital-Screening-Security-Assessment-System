import json

from conftest import fixture_document
from sentinel_ai.gateway import ROOT


def test_authentication_and_no_free_prompt(gateway):
    assert gateway.client.get(ROOT + "/health").status_code == 401
    assert gateway.client.get(ROOT + "/health", headers=gateway.token(ttl=-1)).status_code == 401
    token = gateway.token()
    token["Authorization"] = token["Authorization"][:-3] + "aaa"
    assert gateway.client.get(ROOT + "/health", headers=token).status_code == 401
    assert gateway.get("/health", scopes={"ai.analysis.execute"}).status_code == 403
    assert (
        gateway.client.get(ROOT + "/health", headers={"Authorization": "Bearer " + "7" * 64}).status_code
        == 401
    )
    assert gateway.send("/chat", {"prompt": "TEST untyped input"}).status_code == 404
    assert (
        gateway.send(
            "/analyze/vulnerability",
            {"kind": "vulnerability", "cve": "CVE-2021-44228"},
            scopes={"ai.analysis.execute"},
        ).status_code
        == 403
    )
    assert gateway.get("/health").json()["status"] == "not_configured"


def test_privacy_and_schema_errors_redacted(gateway):
    unknown = gateway.send(
        "/analyze/vulnerability",
        {"kind": "vulnerability", "cve": "CVE-2021-44228", "private_field": "TEST sensitive input"},
    )
    assert unknown.status_code == 422 and b"TEST sensitive input" not in unknown.content
    assert (
        gateway.send("/analyze/vulnerability", {"kind": "vulnerability", "cve": "TEST-INVALID"}).status_code
        == 422
    )
    url = {"kind": "threat", "type": "url", "indicator": "https://example.test/?secret=private"}
    assert gateway.send("/analyze/threat", url).status_code == 422
    assert (
        gateway.send("/analyze/threat", url | {"indicator": "https://user:pass@example.test"}).status_code
        == 422
    )
    assert (
        gateway.send("/analyze/other", {"kind": "other", "instruction": "TEST untyped request"}).status_code
        == 422
    )
    invalid = fixture_document() | {
        "content": "TEST private contact in an invalid advisory example person@example.test"
    }
    assert gateway.send("/knowledge/documents", invalid).status_code == 422
    invalid = fixture_document() | {"reference": "https://unapproved.test/reference"}
    assert gateway.send("/knowledge/documents", invalid).status_code == 422
    too_long = gateway.client.post(
        ROOT + "/analyze/threat",
        headers=gateway.token() | {"Content-Type": "application/json"},
        content=b"a" * 220000,
    )
    assert too_long.status_code == 413


def test_approval_search_grounded_inference_and_peer_review(gateway):
    source = fixture_document()
    submitted = gateway.send("/knowledge/documents", source)
    assert submitted.status_code == 201
    doc = submitted.json()["id"]
    assert gateway.get("/knowledge/search?q=Log4j").json()["documents"] == []
    assert gateway.send(f"/knowledge/documents/{doc}/approve", {"reviewed": True}).status_code == 409
    assert "SPRING_TEST_INJECTION_FIELD" in gateway.get(f"/knowledge/documents/{doc}", 2).json()["content"]
    assert gateway.send(f"/knowledge/documents/{doc}/approve", {"reviewed": True}, 2).status_code == 200
    assert gateway.send("/knowledge/documents", source).status_code == 409
    model = gateway.model()
    assert gateway.get("/health").json()["active_model"] == "test-inference:latest"
    accepted = gateway.send("/analyze/vulnerability", {"kind": "vulnerability", "cve": "CVE-2021-44228"})
    job = accepted.json()["id"]
    completed = gateway.wait(job)
    assert completed["state"] == "requires_review", completed
    result = completed["result"]
    assert result["technical_findings"][0]["values"]["cvss"] == 10
    assert result["source_references"][0]["document_id"] == doc
    assert result["source_references"][0]["stale"]
    assert result["model_version"] == "a" * 64
    plan_inputs = [body for _, path, body in gateway.calls if path == "/api/generate"]
    assert plan_inputs and "SPRING_TEST_INJECTION_FIELD" not in json.dumps(plan_inputs)
    assert "https://www.cisa.gov" not in json.dumps(plan_inputs)
    assert gateway.get("/tasks/" + job, 2, {"ai.analysis.execute"}).status_code == 404
    assert gateway.send("/tasks/" + job + "/review", {"decision": "verified"}).status_code == 409
    assert gateway.send("/tasks/" + job + "/review", {"decision": "verified"}, 2).status_code == 200
    assert gateway.get("/tasks/" + job).json()["result"]["review_status"] == "verified"
    assert "SPRING_TEST_INJECTION_FIELD" not in gateway.get("/audit").text
    assert gateway.get("/status").json()["performance"]["tokens"] == 22
    assert gateway.send(f"/models/{model}/activation", {"active": False}).status_code == 200


def test_no_reference_abstains_without_fake_inference(gateway):
    answer = gateway.send("/analyze/vulnerability", {"kind": "vulnerability", "cve": "CVE-9999-999999999"})
    task = gateway.wait(answer.json()["id"])
    assert task["state"] == "requires_review"
    assert task["result"]["status"] == "insufficient_evidence"
    assert task["result"]["model_name"] is None
    assert not [event for event in gateway.calls if event[1] == "/api/generate"]
    assert gateway.send("/tasks/" + task["id"] + "/review", {"decision": "verified"}, 2).status_code == 409


def test_invalid_selection_or_changed_model_fails_closed(gateway):
    gateway.approve()
    gateway.model()
    gateway.mode["invalid"] = True
    data = {"kind": "vulnerability", "cve": "CVE-2021-44228"}
    task = gateway.send("/analyze/vulnerability", data).json()["id"]
    failure = gateway.wait(task)
    assert (failure["state"], failure["error_code"], failure["result"]) == (
        "failed",
        "ungrounded_output",
        None,
    )
    gateway.mode.update(invalid=False, drift=True)
    task = gateway.send("/analyze/vulnerability", data).json()["id"]
    assert gateway.wait(task)["error_code"] == "model_digest_unavailable"


def test_faiss_hybrid_index_and_archive_enforcement(gateway):
    gateway.model("embedding")
    doc, index = gateway.approve(embed=True)
    assert gateway.wait(index, 2)["result"]["indexed_chunks"] >= 1
    search = gateway.get("/knowledge/search?q=Log4j")
    assert search.json()["retrieval"]["method"] == "hybrid"
    assert search.json()["documents"][0]["document_id"] == doc
    assert gateway.send(f"/knowledge/documents/{doc}/archive", None, 2).status_code == 200
    assert gateway.get("/knowledge/search?q=Log4j").json()["documents"] == []
    assert gateway.app.state.store.one("SELECT COUNT(*) AS size FROM embeddings")["size"] == 0


def test_evaluation_runs_retrieval_on_present_and_missing_cases(gateway):
    gateway.approve()
    job = gateway.send("/evaluation").json()["id"]
    evaluated = gateway.wait(job)
    assert evaluated["result"]["passed"] == 2 and evaluated["result"]["total"] == 2


def test_configuration_without_reference_preserves_typed_observations(gateway):
    job = gateway.send(
        "/analyze/configuration",
        {"kind": "configuration", "platform": "windows", "controls": {"firewall": "fail"}},
    ).json()["id"]
    result = gateway.wait(job)["result"]
    assert result["status"] == "insufficient_evidence"
    assert result["technical_findings"][0]["values"] == {"control": "firewall", "status": "fail"}
    assert (
        gateway.send(
            "/analyze/configuration",
            {"kind": "configuration", "platform": "windows", "controls": {"free_text": "fail"}},
        ).status_code
        == 422
    )
