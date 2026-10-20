#!/usr/bin/env python3
"""End-to-end test against a running deployment, through the web app's /api proxy (the browser's path).

Usage: python3 scripts/e2e.py [web_url] [api_url]   (needs DEMO_ENABLED=true; never point at production)
Event ingestion is server-to-server, so that part calls the API directly.
"""
import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

WEB = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000").rstrip("/")
DIRECT = (sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000").rstrip("/") + "/v1"


def call(method, path, body=None, headers=None, raw=False, base=WEB + "/api"):
    req = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode()
            return r.status, text if raw else json.loads(text or "null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "null")


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        sys.exit(1)


def tenant(org):
    s, d = call("POST", "/auth/register", {"email": f"e2e-{uuid.uuid4().hex[:8]}@example.com", "password": "correct-horse-1",
                                           "organization_name": org})
    check(f"register {org}", s == 201, d)
    return {"Authorization": f"Bearer {d['token']}", "X-Org-Id": d["organizations"][0]["id"]}


h = tenant("E2E Acme")
s, seed = call("POST", "/demo/seed", {}, h)
check("seed sandbox", s == 200 and seed["seeded"], seed)

# Final acceptance flow (PRD §27): agent 5x budget -> DENY -> incident + RCA -> approved remediation -> verified -> resolved
s, r = call("POST", "/demo/scenarios/budget_guardrail", {}, h)
check("5x budget denied before execution", r["decision"] == "DENY" and r["result"] is None, r)
inc = next(i for i in call("GET", "/incidents", None, h)[1] if i["kind"] == "policy_violation")
d = call("GET", f"/incidents/{inc['id']}", None, h)[1]
check("incident has timeline and ranked hypotheses", d["rca"]["timeline"] and d["rca"]["hypotheses"], d.get("rca"))
check("hypotheses unverified without human feedback", not any(x.get("verified") for x in d["rca"]["hypotheses"]))
s, plan = call("POST", "/remediations/plan", {"incident_id": inc["id"]}, h)
suspend = next(p for p in plan if p["action_type"] == "cs.agent.suspend")
s, r = call("POST", f"/remediations/{suspend['id']}/execute", {}, h)
check("remediation refuses without confirmation", s == 422, r)
s, r = call("POST", f"/remediations/{suspend['id']}/execute", {"confirm": True}, h)
check("remediation executed and verified", r["status"] == "verified", r)
check("incident resolved", call("GET", f"/incidents/{inc['id']}", None, h)[1]["status"] == "resolved")
s, report = call("GET", f"/incidents/{inc['id']}/report", None, h, raw=True)
check("incident report exported", s == 200 and "Blocked" in report, report[:200])
agent = next(a for a in call("GET", "/agents", None, h)[1] if a["name"] == "Budget optimizer agent")
check("agent suspended", agent["status"] == "suspended", agent)
call("PATCH", f"/agents/{agent['id']}", {"status": "active"}, h)

# Approval: executes exactly once, second decision refused
s, r = call("POST", "/demo/scenarios/budget_approval", {}, h)
check("+50% budget needs approval", r["decision"] == "REQUIRE_APPROVAL", r)
ap = next(a for a in call("GET", "/approvals?status=pending", None, h)[1] if a["action_id"] == r["action_id"])
s, r1 = call("POST", f"/approvals/{ap['id']}/approve", {"note": "e2e"}, h)
check("approval executes action", s == 200 and r1["status"] == "executed", r1)
s, r2 = call("POST", f"/approvals/{ap['id']}/approve", {}, h)
check("second approval refused", s == 409, (s, r2))

# Real agent key through the gateway: same idempotency key twice -> one action
agent_h = {"Authorization": f"Bearer {seed['agent_keys']['Budget optimizer agent']}"}
camp = call("GET", "/campaigns", None, h)[1][0]
env = {"action_type": "ads.campaign.update_budget", "target": {"campaign_id": camp["id"]},
       "parameters": {"proposed_daily_budget": round(camp["daily_budget"] * 1.05, 2), "currency": camp["currency"]},
       "idempotency_key": f"e2e-{uuid.uuid4().hex[:8]}"}
s, a1 = call("POST", "/actions/execute", env, agent_h)
s, a2 = call("POST", "/actions/execute", env, agent_h)
check("agent +5% budget allowed", a1["decision"] == "ALLOW" and a1["status"] == "executed", a1)
check("retry with same idempotency key is not re-executed", a2["action_id"] == a1["action_id"] and a2.get("duplicate"), a2)
s, r = call("POST", "/actions/execute", {**env, "action_type": "cs.agent.suspend", "idempotency_key": "x1"}, agent_h)
check("agent cannot call internal cs.* actions", r["decision"] == "DENY", r)
s, r = call("POST", "/actions/execute", env, {"Authorization": "Bearer csa_bogus"})
check("bad agent key rejected", s == 401, r)

# Remaining scenarios open the right incident kinds
for name in ("duplicate_outreach", "spend_spike", "silent_failure", "config_failure"):
    s, r = call("POST", f"/demo/scenarios/{name}", {}, h)
    check(f"scenario {name}", s == 200, r)
kinds = {i["kind"] for i in call("GET", "/incidents", None, h)[1]}
want = {"policy_violation", "duplicate_action", "spend_anomaly", "missing_heartbeat", "workflow_failure"}
check("all scenario incidents present", want <= kinds, kinds)

# Ingestion: authenticated, idempotent on event_id, malformed events quarantined
ingest_h = {"X-CampaignShield-Key": seed["n8n_ingest_key"]}
ev = {"event_id": f"e2e-{uuid.uuid4().hex}", "source": "n8n", "event_type": "workflow.execution.succeeded",
      "occurred_at": datetime.now(timezone.utc).isoformat()}
s, r1 = call("POST", "/events", ev, ingest_h, base=DIRECT)
s, r2 = call("POST", "/events", ev, ingest_h, base=DIRECT)
check("event accepted then deduplicated", r1["accepted"] == 1 and r2["duplicates"] == 1, (r1, r2))
s, r = call("POST", "/events", {"event_id": "bad", "source": "n8n"}, ingest_h, base=DIRECT)
check("malformed event quarantined", r["quarantined"] == 1, r)
check("ingest without key rejected", call("POST", "/events", ev, base=DIRECT)[0] == 401)

# Tenant isolation: another org sees nothing and gets 404 with no metadata
other = tenant("E2E Other")
s, r = call("GET", f"/incidents/{inc['id']}", None, other)
check("cross-tenant read is 404", s == 404 and inc["id"] not in json.dumps(r), (s, r))
check("cross-tenant org header refused", call("GET", "/incidents", None, {**other, "X-Org-Id": h["X-Org-Id"]})[0] == 404)
check("other tenant list empty", call("GET", "/incidents", None, other)[1] == [])

# Kill switch denies every gateway action
call("PATCH", f"/organizations/{h['X-Org-Id']}", {"kill_switch": True}, h)
s, r = call("POST", "/actions/execute", {**env, "idempotency_key": f"e2e-{uuid.uuid4().hex[:8]}"}, agent_h)
check("kill switch denies actions", r["decision"] == "DENY", r)
call("PATCH", f"/organizations/{h['X-Org-Id']}", {"kill_switch": False}, h)

# Audit chain, dashboard, logout
s, r = call("GET", "/audit/verify", None, h)
check("audit hash chain valid", r["valid"], r)
s, r = call("GET", "/dashboard/summary?days=7", None, h)
check("dashboard summary", s == 200 and r["protection"]["actions_blocked"] >= 2, r.get("protection"))
call("POST", "/auth/logout", {}, h)
check("session revoked on logout", call("GET", "/incidents", None, h)[0] == 401)

for page in ("/login", "/", "/incidents", "/policies", "/approvals", "/integrations", "/workflows", "/campaigns", "/audit", "/settings"):
    with urllib.request.urlopen(WEB + page, timeout=30) as r:
        check(f"page {page}", r.status == 200)
print("e2e passed")
