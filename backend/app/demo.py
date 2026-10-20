"""Sandbox data and the PRD demonstration scenarios. Everything runs through the real ingestion, gateway and detection paths."""

import math
import random
import uuid
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select

from . import connectors, detection, gateway, policy
from .core import audit, emit
from .db import utcnow
from .ingestion import ingest
from .models import Agent, Campaign, CampaignMetric, Integration, Policy, Workflow
from .security import new_api_key

WORKFLOWS = [
    ("wf-lead-sync", "Lead sync → CRM", 15, {"endpoint": "https://api.crm.example/v2/leads", "retry_on_fail": True}),
    ("wf-budget-opt", "Daily budget optimizer", 60, {"endpoint": "https://ads.example/v1/budgets", "currency_field": "USD"}),
    ("wf-press", "Press release distribution", None, {"retry_on_fail": True, "max_tries": 3}),
]
CAMPAIGNS = [
    ("1001", "Brand Search — US", 400.0, "USD", "America/New_York"),
    ("1002", "Retargeting — Holiday", 800.0, "USD", "America/New_York"),
    ("1003", "Prospecting — EU", 300.0, "EUR", "Europe/Berlin"),
]


def _integration(db, org, provider, name):
    integ = db.scalar(select(Integration).where(Integration.organization_id == org.id, Integration.provider == provider,
                                                Integration.mode == "sandbox", Integration.status != "revoked"))
    if integ:
        return integ, None
    key, key_hash, prefix = new_api_key("csi")
    integ = Integration(organization_id=org.id, provider=provider, name=name, mode="sandbox", config={"demo": True},
                        ingest_key_hash=key_hash, ingest_key_prefix=prefix, health={"last_ok_at": utcnow().isoformat()})
    integ.capabilities = connectors.capabilities(integ)
    db.add(integ)
    db.flush()
    return integ, key


def seed(db, org, actor: str) -> dict:
    n8n, n8n_key = _integration(db, org, "n8n", "n8n (sandbox)")
    ads, _ = _integration(db, org, "google_ads", "Google Ads (sandbox)")
    _integration(db, org, "outreach", "PR outreach (sandbox)")
    now = utcnow()
    rnd = random.Random(42)  # noqa: S311 (demo data)

    for ext, name, interval, cfg in WORKFLOWS:
        if db.scalar(select(Workflow.id).where(Workflow.integration_id == n8n.id, Workflow.external_id == ext)):
            continue
        db.add(Workflow(organization_id=org.id, integration_id=n8n.id, external_id=ext, name=name, expected_interval_minutes=interval, config=cfg))
        db.flush()
        step = interval or 240
        execs = []
        for i in range(int(24 * 60 / step), 0, -1):
            start = now - timedelta(minutes=i * step)
            execs.append({"n8n": {"id": f"{ext}-{i}", "workflowId": ext, "workflowName": name, "status": "success", "mode": "trigger",
                                  "startedAt": start.isoformat(), "stoppedAt": (start + timedelta(seconds=rnd.uniform(2, 9))).isoformat()}})
        ingest(db, org, n8n, execs)

    for ext, name, budget, cur, tz in CAMPAIGNS:
        if db.scalar(select(Campaign.id).where(Campaign.integration_id == ads.id, Campaign.external_id == ext)):
            continue
        camp = Campaign(organization_id=org.id, integration_id=ads.id, external_id=ext, name=name, daily_budget=budget,
                        currency=cur, timezone=tz, last_synced_at=now)
        db.add(camp)
        db.flush()
        hour0 = now.replace(minute=0, second=0, microsecond=0)
        for h in range(14 * 24, 0, -1):
            b = hour0 - timedelta(hours=h)
            diurnal = 0.4 + 0.9 * max(0.0, math.sin((b.hour - 6) / 24 * 2 * math.pi))
            spend = round(budget / 24 * diurnal * rnd.uniform(0.85, 1.15), 2)
            db.add(CampaignMetric(organization_id=org.id, campaign_id=camp.id, bucket_start=b, spend=spend,
                                  impressions=int(spend * 90), clicks=int(spend * 2.5), conversions=round(spend * 0.08, 1)))
        camp.metrics_as_of = hour0 - timedelta(hours=1)

    agents = {}
    for name, allowed in [("Budget optimizer agent", ["ads.*", "n8n.workflow.*"]), ("PR outreach agent", ["outreach.email.send"])]:
        if not db.scalar(select(Agent.id).where(Agent.organization_id == org.id, Agent.name == name)):
            key, key_hash, prefix = new_api_key("csa")
            db.add(Agent(organization_id=org.id, name=name, key_hash=key_hash, key_prefix=prefix, allowed_actions=allowed))
            agents[name] = key

    for key, template, name, rules in [
        ("campaign_budget_protection", "budget_protection", "Campaign budget protection", {}),
        ("budget_hard_cap", "budget_protection", "Hard budget ceiling",
         {"max_increase_percent": 1000.0, "max_daily_budget": 2500.0, "on_violation": "deny"}),
        ("agent_rate_limit", "agent_rate_limit", "Agent rate limit", {}),
        ("idempotency_required", "idempotency_required", "Idempotency keys required", {}),
        ("outreach_guard", "outreach_guard", "Outreach send guard", {"blocked_domains": ["competitor.example"]}),
    ]:
        if not db.scalar(select(Policy.id).where(Policy.organization_id == org.id, Policy.key == key)):
            db.add(Policy(organization_id=org.id, key=key, name=name, template=template, rules=policy.validate_rules(template, rules)))
    audit(db, org.id, actor, "demo.seeded", f"organization:{org.id}", {})
    db.commit()
    return {"seeded": True, "n8n_ingest_key": n8n_key, "agent_keys": agents,
            "note": "Keys are shown once. Sandbox integrations never touch real ad accounts."}


def _agent(db, org, name):
    agent = db.scalar(select(Agent).where(Agent.organization_id == org.id, Agent.name == name))
    if not agent:
        raise HTTPException(409, "Seed demo data first")
    if agent.status != "active":  # demo re-runs: a previous remediation may have suspended it
        agent.status = "active"
    return agent


def _wf(db, org, ext):
    wf = db.scalar(select(Workflow).where(Workflow.organization_id == org.id, Workflow.external_id == ext))
    if not wf:
        raise HTTPException(409, "Seed demo data first")
    return wf


def _camp(db, org, ext):
    c = db.scalar(select(Campaign).where(Campaign.organization_id == org.id, Campaign.external_id == ext))
    if not c:
        raise HTTPException(409, "Seed demo data first")
    return c


def run(db, org, name: str, actor: str) -> dict:
    tag = uuid.uuid4().hex[:6]
    if name == "budget_guardrail":
        camp = _camp(db, org, "1002")
        env = gateway.ActionEnvelope(action_type="ads.campaign.update_budget", target={"campaign_id": camp.id},
                                     parameters={"proposed_daily_budget": camp.daily_budget * 5, "currency": camp.currency},
                                     idempotency_key=f"budget-{tag}", reason="Holiday demand is high; maximize reach.")
        return gateway.submit(db, org, env, _agent(db, org, "Budget optimizer agent"))

    if name == "budget_approval":
        camp = _camp(db, org, "1001")
        env = gateway.ActionEnvelope(action_type="ads.campaign.update_budget", target={"campaign_id": camp.id},
                                     parameters={"proposed_daily_budget": round(camp.daily_budget * 1.5, 2), "currency": camp.currency},
                                     idempotency_key=f"budget-{tag}", reason="CPA is below target; scale up.")
        return gateway.submit(db, org, env, _agent(db, org, "Budget optimizer agent"))

    if name == "duplicate_outreach":
        agent = _agent(db, org, "PR outreach agent")
        params = {"campaign": "q4-launch", "subject": "Embargoed: Q4 product launch",
                  "recipients": [f"editor{i}@press{i % 4}.example" for i in range(12)], "simulate_timeout": True}
        env = gateway.ActionEnvelope(action_type="outreach.email.send", target={"channel": "email"}, parameters=params,
                                     idempotency_key=f"press-{tag}", trace_id=f"trace-press-{tag}")
        first = gateway.submit(db, org, env, agent)
        retry = gateway.submit(db, org, env.model_copy(update={"parameters": {**params, "simulate_timeout": False}}), agent)
        return {"original": first, "retry": retry}

    if name == "spend_spike":  # monitoring-only: the change happens outside the gateway
        camp = _camp(db, org, "1001")
        bucket = utcnow().replace(minute=0, second=0, microsecond=0)
        emit(db, org.id, "campaign.budget.changed", resource_type="campaign", resource_id=camp.id, integration_id=camp.integration_id,
             severity="low", occurred_at=bucket - timedelta(minutes=40),
             payload={"from": camp.daily_budget, "to": camp.daily_budget * 6, "observed_via": "sync", "changed_outside_gateway": True})
        camp.daily_budget *= 6
        baseline = db.scalars(select(CampaignMetric.spend).where(CampaignMetric.campaign_id == camp.id)
                              .order_by(CampaignMetric.bucket_start.desc()).limit(24)).all()
        connectors.record_metric(db, org, camp, bucket, round(max(baseline) * 8, 2), 40_000, 900, 4)
        db.commit()
        return {"campaign": camp.name, "note": "Detected from provider metrics; CampaignShield could not block this change."}

    n8n = db.scalar(select(Integration).where(Integration.organization_id == org.id, Integration.provider == "n8n", Integration.mode == "sandbox"))
    if name == "silent_failure":
        wf = _wf(db, org, "wf-lead-sync")
        t = utcnow() - timedelta(hours=3)
        ingest(db, org, n8n, [{"n8n": {"id": f"ls-fail-{tag}", "workflowId": wf.external_id, "workflowName": wf.name, "status": "error",
                                       "startedAt": t.isoformat(), "stoppedAt": (t + timedelta(seconds=30)).isoformat(),
                                       "error": {"message": "503 Service Unavailable from api.crm.example", "node": "HTTP Request"}}}])
        wf.last_execution_at = t
        detection.check_heartbeats(db, org)
        db.commit()
        return {"workflow": wf.name, "note": "No executions for 3 hours although the workflow is enabled."}

    if name == "config_failure":
        wf = _wf(db, org, "wf-budget-opt")
        wf.previous_config, wf.config = dict(wf.config), {**wf.config, "currency_field": None, "endpoint": "https://ads.example/v3/budgets"}
        t0 = utcnow() - timedelta(minutes=20)
        emit(db, org.id, "workflow.config.changed", source="n8n", resource_type="workflow", resource_id=wf.external_id,
             integration_id=n8n.id, occurred_at=t0, payload={"from_version": wf.version, "to_version": f"{wf.version}.{tag}"})
        ingest(db, org, n8n, [{"n8n": {"id": f"bo-{tag}-{i}", "workflowId": wf.external_id, "workflowName": wf.name, "status": "error",
                                       "startedAt": (t0 + timedelta(minutes=5 * i)).isoformat(),
                                       "stoppedAt": (t0 + timedelta(minutes=5 * i, seconds=2)).isoformat(),
                                       "error": {"message": "400 Bad Request: invalid parameter 'currency'", "node": "Update budget"}}}
                              for i in range(1, 4)])
        return {"workflow": wf.name}
    raise HTTPException(404, "Unknown scenario")


SCENARIOS = {
    "budget_guardrail": "Agent tries to 5× a campaign budget — blocked by the hard ceiling",
    "budget_approval": "Agent asks for +50% budget — routed for human approval",
    "duplicate_outreach": "Timeout causes a retried press-release send — duplicate suppressed",
    "spend_spike": "Budget changed outside the gateway; spend spikes (monitoring only)",
    "silent_failure": "Lead sync stops running after an upstream outage",
    "config_failure": "Bad config change makes a workflow fail repeatedly",
}
