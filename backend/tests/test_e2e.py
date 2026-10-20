"""API-level end-to-end and security tests (PRD 16.5, 16.6, UT-04/05/06/08/09/10, final acceptance test)."""

import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor

from conftest import Tenant

from app import gateway


def _campaign(t, ext):
    return next(c for c in t.get("/v1/campaigns").json() if c["external_id"] == ext)


def _n8n_integration(t):
    r = t.post("/v1/integrations", {"provider": "n8n", "name": "n8n", "mode": "sandbox"})
    assert r.status_code == 201, r.text
    return r.json()


def test_e2e01_onboarding_and_ingestion(client, tenant):
    integ = _n8n_integration(tenant)
    assert integ["ingest_key"].startswith("csi_") and "ingest_key_hash" not in integ
    assert integ["capabilities"]["enforcement"] == "gateway"
    ev = {"n8n": {"id": "1", "workflowId": "wf1", "workflowName": "Lead sync", "status": "success",
                  "startedAt": "2026-10-20T08:00:00Z", "stoppedAt": "2026-10-20T08:00:02Z"}}
    r = client.post("/v1/events", json=ev, headers={"X-CampaignShield-Key": integ["ingest_key"]})
    assert r.status_code == 202 and r.json()["accepted"] == 1
    wfs = tenant.get("/v1/workflows").json()
    assert wfs[0]["name"] == "Lead sync" and wfs[0]["last_status"] == "succeeded"
    events = tenant.get("/v1/events").json()["items"]
    assert events[0]["trace_id"] == "n8n-exec-1"
    assert tenant.get("/v1/dashboard/summary").json()["workflows"]["monitored"] == 1


def test_ingestion_dedup_quarantine_out_of_order_and_auth(client, tenant):
    integ = _n8n_integration(tenant)
    h = {"X-CampaignShield-Key": integ["ingest_key"]}
    base = {"source": "custom", "event_type": "workflow.execution.succeeded", "resource": {"type": "workflow", "id": "w"}}
    newer = {**base, "event_id": "e2", "occurred_at": "2026-10-20T09:00:00Z"}
    older = {**base, "event_id": "e1", "occurred_at": "2026-10-20T08:00:00Z", "event_type": "workflow.execution.failed"}
    bad = {"event_id": "e3", "source": "x", "event_type": "NOT VALID", "occurred_at": "nope"}
    r = client.post("/v1/events", json={"events": [newer, older, newer, bad]}, headers=h).json()
    assert r == {**r, "accepted": 2, "duplicates": 1, "quarantined": 1}  # UT-05
    wf = tenant.get("/v1/workflows").json()[0]
    assert wf["last_status"] == "succeeded"  # out-of-order failure did not overwrite newer state
    assert len(tenant.get("/v1/events/quarantine").json()) == 1
    assert client.post("/v1/events", json=newer, headers={"X-CampaignShield-Key": "csi_wrong"}).status_code == 401
    assert client.post("/v1/events", json=newer).status_code == 401


def test_webhook_signature_required(client, tenant):
    integ = tenant.post("/v1/integrations", {"provider": "n8n", "name": "signed", "require_signature": True}).json()
    body = json.dumps({"event_id": "s1", "source": "n8n", "event_type": "workflow.execution.succeeded", "occurred_at": "2026-10-20T08:00:00Z"}).encode()
    h = {"X-CampaignShield-Key": integ["ingest_key"], "Content-Type": "application/json"}
    assert client.post("/v1/events", content=body, headers=h).status_code == 401
    ts = str(int(time.time()))
    sig = hmac.new(integ["signing_secret"].encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert client.post("/v1/events", content=body, headers={**h, "X-CS-Timestamp": ts, "X-CS-Signature": sig}).status_code == 202
    forged = hmac.new(b"guess", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert client.post("/v1/events", content=body, headers={**h, "X-CS-Timestamp": ts, "X-CS-Signature": forged}).status_code == 401


def test_e2e03_budget_guardrail_blocks_before_execution(client, tenant):
    keys = tenant.seed()["agent_keys"]
    camp = _campaign(tenant, "1002")
    env = {"action_type": "ads.campaign.update_budget", "target": {"campaign_id": camp["id"]},
           "parameters": {"proposed_daily_budget": 4000, "currency": "USD"}, "idempotency_key": "budget-change-123"}
    r = client.post("/v1/actions/execute", json=env, headers=tenant.agent_headers(keys["Budget optimizer agent"]))
    assert r.status_code == 200 and r.json()["decision"] == "DENY" and r.json()["status"] == "denied"
    assert _campaign(tenant, "1002")["daily_budget"] == 800  # downstream never touched
    incidents = tenant.get("/v1/incidents").json()
    assert incidents[0]["kind"] == "policy_violation" and incidents[0]["severity"] == "high"
    detail = tenant.get(f"/v1/incidents/{incidents[0]['id']}").json()
    assert detail["decisions"][0]["policy_refs"] and detail["rca"]["timeline"]
    assert any("policy" in h["cause"] for h in detail["rca"]["hypotheses"])
    assert not detail["rca"]["hypotheses"][0]["verified"]  # FR-RCA-011
    assert any(a["action"] == "action.decision" for a in tenant.get("/v1/audit").json()["items"])


def test_budget_approval_flow_executes_once(client, tenant):
    keys = tenant.seed()["agent_keys"]
    camp = _campaign(tenant, "1001")
    env = {"action_type": "ads.campaign.update_budget", "target": {"campaign_id": camp["id"]},
           "parameters": {"proposed_daily_budget": 600, "currency": "USD"}, "idempotency_key": "raise-1"}
    r = client.post("/v1/actions/execute", json=env, headers=tenant.agent_headers(keys["Budget optimizer agent"])).json()
    assert r["status"] == "pending_approval"
    ap = tenant.get("/v1/approvals?status=pending").json()[0]
    assert ap["required_role"] == "admin"
    assert tenant.post(f"/v1/approvals/{ap['id']}/approve", {"note": "ok"}).json()["status"] == "executed"
    assert tenant.post(f"/v1/approvals/{ap['id']}/approve").status_code == 409  # UT-10
    assert _campaign(tenant, "1001")["daily_budget"] == 600
    executed = [e for e in tenant.get("/v1/events?event_type=action.executed").json()["items"]]
    assert len(executed) == 1


def test_stale_approval_is_not_executed(client, tenant):
    keys = tenant.seed()["agent_keys"]
    camp = _campaign(tenant, "1001")
    h = tenant.agent_headers(keys["Budget optimizer agent"])
    client.post("/v1/actions/execute", headers=h, json={"action_type": "ads.campaign.update_budget", "target": {"campaign_id": camp["id"]},
                                                        "parameters": {"proposed_daily_budget": 700}, "idempotency_key": "a-1"})
    client.post("/v1/actions/execute", headers=h, json={"action_type": "ads.campaign.update_budget", "target": {"campaign_id": camp["id"]},
                                                        "parameters": {"proposed_daily_budget": 450}, "idempotency_key": "a-2"})
    assert _campaign(tenant, "1001")["daily_budget"] == 450
    ap = tenant.get("/v1/approvals?status=pending").json()[0]
    r = tenant.post(f"/v1/approvals/{ap['id']}/approve").json()
    assert r["status"] == "rejected" and r["result"]["error"] == "stale_state"
    assert _campaign(tenant, "1001")["daily_budget"] == 450


def test_e2e02_duplicate_action_prevention(client, tenant):
    tenant.seed()
    r = tenant.post("/v1/demo/scenarios/duplicate_outreach").json()
    assert r["original"]["status"] == "unknown"  # timeout after delivery
    assert r["retry"]["duplicate"] is True and r["retry"]["status"] == "executed"  # reconciled, not re-sent
    sent = tenant.get("/v1/events?event_type=provider.outreach.sent").json()["items"]
    assert len(sent) == 1
    inc = next(i for i in tenant.get("/v1/incidents").json() if i["kind"] == "duplicate_action")
    rca = tenant.get(f"/v1/incidents/{inc['id']}").json()["rca"]
    assert rca["hypotheses"][0]["cause"].startswith("Client retried after a downstream timeout")
    timeline_ids = {t["event_id"] for t in rca["timeline"]}
    assert all(e in timeline_ids for e in rca["hypotheses"][0]["evidence_ids"])  # evidence references are valid


def test_concurrent_duplicate_requests_execute_once(client, tenant):
    keys = tenant.seed()["agent_keys"]
    h = tenant.agent_headers(keys["PR outreach agent"])
    env = {"action_type": "outreach.email.send", "target": {}, "idempotency_key": "concurrent-1",
           "parameters": {"campaign": "x", "recipients": ["a@b.example"], "subject": "hi"}}
    with ThreadPoolExecutor(4) as pool:
        codes = list(pool.map(lambda _: client.post("/v1/actions/execute", json=env, headers=h).status_code, range(4)))
    assert all(c == 200 for c in codes)
    assert len(tenant.get("/v1/events?event_type=provider.outreach.sent").json()["items"]) == 1


def test_idempotency_key_reuse_with_different_params_conflicts(client, tenant):
    keys = tenant.seed()["agent_keys"]
    h = tenant.agent_headers(keys["PR outreach agent"])
    env = {"action_type": "outreach.email.send", "target": {}, "idempotency_key": "k-1", "parameters": {"recipients": ["a@b.example"]}}
    assert client.post("/v1/actions/execute", json=env, headers=h).status_code == 200
    env["parameters"]["recipients"] = ["c@d.example"]
    assert client.post("/v1/actions/execute", json=env, headers=h).status_code == 409


def test_ut08_policy_engine_failure_fails_closed(client, tenant, monkeypatch):
    keys = tenant.seed()["agent_keys"]

    def boom(*a, **k):
        raise RuntimeError("policy store unavailable")

    monkeypatch.setattr(gateway.policy, "evaluate", boom)
    camp = _campaign(tenant, "1001")
    r = client.post("/v1/actions/execute", headers=tenant.agent_headers(keys["Budget optimizer agent"]),
                    json={"action_type": "ads.campaign.update_budget", "target": {"campaign_id": camp["id"]},
                          "parameters": {"proposed_daily_budget": 401}, "idempotency_key": "fc-1"}).json()
    assert r["decision"] == "DENY" and r["decision"] and _campaign(tenant, "1001")["daily_budget"] == 400


def test_agent_cannot_use_internal_or_unpermitted_actions(client, tenant):
    keys = tenant.seed()["agent_keys"]
    h = tenant.agent_headers(keys["PR outreach agent"])
    camp = _campaign(tenant, "1001")
    for env in ({"action_type": "ads.campaign.pause", "target": {"campaign_id": camp["id"]}, "idempotency_key": "p-1"},
                {"action_type": "cs.agent.suspend", "target": {"agent_id": "x"}, "idempotency_key": "p-2"},
                {"action_type": "ads.account.delete", "target": {}, "idempotency_key": "p-3"}):
        assert client.post("/v1/actions/execute", json=env, headers=h).json()["decision"] == "DENY"
    assert client.post("/v1/actions/execute", json={"action_type": "x.y"}, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_e2e04_workflow_failure_investigation_and_e2e05_remediation(tenant):
    tenant.seed()
    tenant.post("/v1/demo/scenarios/config_failure")
    inc = next(i for i in tenant.get("/v1/incidents").json() if i["kind"] == "workflow_failure")
    detail = tenant.get(f"/v1/incidents/{inc['id']}").json()
    top = detail["rca"]["hypotheses"][0]
    assert top["cause"] == "Configuration change introduced an invalid configuration" and top["evidence_ids"]
    plan = tenant.post("/v1/remediations/plan", {"incident_id": inc["id"]}).json()
    step = next(s for s in plan if s["action_type"] == "n8n.workflow.rollback")
    assert tenant.post(f"/v1/remediations/{step['id']}/execute", {"confirm": False}).status_code == 422
    done = tenant.post(f"/v1/remediations/{step['id']}/execute", {"confirm": True}).json()
    assert done["status"] == "verified" and done["approved_by"]
    assert tenant.post(f"/v1/remediations/{step['id']}/execute", {"confirm": True}).status_code == 409  # executes once
    after = tenant.get(f"/v1/incidents/{inc['id']}").json()
    assert after["status"] == "resolved" and "state verified" in after["resolution"]
    report = tenant.get(f"/v1/incidents/{inc['id']}/report").text
    assert "Hypotheses (inferred" in report and "verified" in report
    assert tenant.get("/v1/audit/verify").json()["valid"] is True


def test_final_acceptance_flow(client, tenant):
    """Agent proposes → denied → incident → timeline → RCA → remediation → approved → verified → audit report."""
    tenant.seed()
    r = tenant.post("/v1/demo/scenarios/budget_guardrail").json()
    assert r["decision"] == "DENY"
    inc = next(i for i in tenant.get("/v1/incidents").json() if i["kind"] == "policy_violation")
    plan = tenant.post("/v1/remediations/plan", {"incident_id": inc["id"]}).json()
    suspend = next(s for s in plan if s["action_type"] == "cs.agent.suspend")
    assert tenant.post(f"/v1/remediations/{suspend['id']}/execute", {"confirm": True}).json()["status"] == "verified"
    agent = next(a for a in tenant.get("/v1/agents").json() if a["name"] == "Budget optimizer agent")
    assert agent["status"] == "suspended"
    final = tenant.get(f"/v1/incidents/{inc['id']}").json()
    assert final["status"] == "resolved"
    assert "Blocked" in tenant.get(f"/v1/incidents/{inc['id']}/report").text


def test_monitoring_only_spend_spike_detected(tenant):
    tenant.seed()
    tenant.post("/v1/demo/scenarios/spend_spike")
    inc = next(i for i in tenant.get("/v1/incidents").json() if i["kind"] == "spend_anomaly")
    d = tenant.get(f"/v1/incidents/{inc['id']}").json()
    ev = next(e for e in d["evidence"] if e["evidence_type"] == "spend_robust_z")
    assert ev["data"]["robust_z"] > 3.5 and "delayed" in ev["data"]["note"]
    assert d["rca"]["hypotheses"][0]["cause"] == "Budget increase enabled the spend spike"
    plan = tenant.post("/v1/remediations/plan", {"incident_id": inc["id"]}).json()
    assert plan[0]["action_type"] == "ads.campaign.pause" and plan[0]["reversibility"] == "reversible"


def test_silent_failure_heartbeat(tenant):
    tenant.seed()
    tenant.post("/v1/demo/scenarios/silent_failure")
    kinds = {i["kind"] for i in tenant.get("/v1/incidents").json()}
    assert "missing_heartbeat" in kinds


def test_e2e06_tenant_isolation(client):
    a, b = Tenant(client, "A"), Tenant(client, "B")
    b.seed()
    b.post("/v1/demo/scenarios/budget_guardrail")
    b_inc = b.get("/v1/incidents").json()[0]["id"]
    b_camp = b.get("/v1/campaigns").json()[0]["id"]
    for path in (f"/v1/incidents/{b_inc}", f"/v1/campaigns/{b_camp}", f"/v1/incidents/{b_inc}/report"):
        r = a.get(path)
        assert r.status_code == 404 and b_inc not in r.text  # UT-09: no metadata leak
    assert client.get("/v1/incidents", headers={**a.h, "X-Org-Id": b.org_id}).status_code == 404
    assert a.get("/v1/incidents").json() == []
    assert a.post("/v1/remediations/plan", {"incident_id": b_inc}).status_code == 404


def test_role_based_authorization(client, tenant):
    tenant.seed()
    assert tenant.post("/v1/members", {"email": "viewer@example.com", "role": "viewer", "temporary_password": "viewer-pass-1"}).status_code == 201
    v = client.post("/v1/auth/login", json={"email": "viewer@example.com", "password": "viewer-pass-1"}).json()
    vh = {"Authorization": f"Bearer {v['token']}", "X-Org-Id": tenant.org_id}
    assert client.get("/v1/incidents", headers=vh).status_code == 200
    assert client.post("/v1/policies", headers=vh, json={"name": "x", "template": "change_freeze"}).status_code == 403
    assert client.post("/v1/demo/scenarios/budget_guardrail", headers=vh).status_code == 403
    assert client.get("/v1/audit", headers=vh).status_code == 403
    client.post("/v1/auth/logout", headers=vh)
    assert client.get("/v1/incidents", headers=vh).status_code == 401  # session revoked


def test_policy_versioning_and_dry_run(tenant):
    tenant.seed()
    r = tenant.post("/v1/policies", {"key": "campaign_budget_protection", "name": "Budget v2", "template": "budget_protection",
                                     "rules": {"max_increase_percent": 50}})
    assert r.status_code == 201 and r.json()["version"] == 2
    pol = next(p for p in tenant.get("/v1/policies").json() if p["key"] == "campaign_budget_protection")
    assert pol["active"]["version"] == 2 and len(pol["versions"]) == 2
    camp = _campaign(tenant, "1001")
    sim = tenant.post("/v1/policies/evaluate", {"action": {"action_type": "ads.campaign.update_budget", "target": {"campaign_id": camp["id"]},
                                                           "parameters": {"proposed_daily_budget": 560}, "idempotency_key": "dry-1"},
                                                "draft": {"key": "campaign_budget_protection", "name": "d", "template": "budget_protection",
                                                          "rules": {"max_increase_percent": 10}}}).json()
    assert sim["dry_run"] and sim["decision"] == "REQUIRE_APPROVAL"
    assert _campaign(tenant, "1001")["daily_budget"] == 400
    assert tenant.post("/v1/policies", {"name": "bad", "template": "budget_protection", "rules": {"max_daily_budget": -5}}).status_code == 422
    assert tenant.get("/v1/policies/campaign_budget_protection/preview").json()[0]["applies"] is not None


def test_integration_health_failure_and_recovery(tenant):
    integ = _n8n_integration(tenant)
    tenant.post(f"/v1/integrations/{integ['id']}/simulate", {"auth_expired": True})
    r = tenant.post(f"/v1/integrations/{integ['id']}/check").json()
    assert r["ok"] is False and r["integration"]["status"] == "auth_expired"
    assert any(i["kind"] == "integration_health" for i in tenant.get("/v1/incidents").json())
    tenant.post(f"/v1/integrations/{integ['id']}/simulate", {})
    assert tenant.post(f"/v1/integrations/{integ['id']}/check").json()["integration"]["status"] == "connected"


def test_error_format_and_health(client):
    r = client.get("/v1/incidents")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated" and r.json()["error"]["request_id"]
    assert client.get("/v1/health").json()["status"] == "ok"
    assert client.get("/v1/ready").json()["status"] == "ready"
    assert "/v1/actions/execute" in client.get("/openapi.json").json()["paths"]
