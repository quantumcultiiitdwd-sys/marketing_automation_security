import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .. import connectors, detection
from ..config import settings
from ..connectors import ProviderError
from ..core import audit
from ..db import get_db, utcnow
from ..deps import Ctx, get_ctx, owned, rate_limit, require
from ..ingestion import ingest
from ..models import (ActionRequest, Agent, Campaign, CampaignMetric, Event, Integration, IntegrationCredential, Organization,
                      PolicyDecision, QuarantinedEvent, Workflow, to_dict)
from ..security import check_url_safe, decrypt, encrypt, new_api_key, sha256, sign, verify_webhook_signature

router = APIRouter(prefix="/v1", tags=["integrations & telemetry"])


def _page(q, limit: int, offset: int, db):
    total = db.scalar(select(func.count()).select_from(q.order_by(None).subquery()))
    return total, db.scalars(q.limit(limit).offset(offset)).all()


# --- integrations -----------------------------------------------------------

class IntegrationCreate(BaseModel):
    provider: str = Field(pattern="^(n8n|google_ads|outreach)$")
    name: str = Field(min_length=1, max_length=200)
    mode: str = Field("sandbox", pattern="^(sandbox|live)$")
    base_url: str | None = Field(None, max_length=500)  # n8n
    api_key: str | None = Field(None, max_length=2000)  # n8n
    customer_id: str | None = Field(None, pattern=r"^\d{3}-?\d{3}-?\d{4}$")  # google ads
    login_customer_id: str | None = Field(None, pattern=r"^\d{3}-?\d{3}-?\d{4}$")
    allow_mutations: bool = False
    require_signature: bool = False


def _integration_out(integ: Integration, db, **extra) -> dict:
    d = to_dict(integ, **extra)
    d["config"] = {k: v for k, v in (integ.config or {}).items() if k not in ("oauth_state",)}
    d["workflows"] = db.scalar(select(func.count()).select_from(Workflow).where(Workflow.integration_id == integ.id))
    d["campaigns"] = db.scalar(select(func.count()).select_from(Campaign).where(Campaign.integration_id == integ.id))
    return d


@router.post("/integrations", status_code=201)
def create_integration(body: IntegrationCreate, ctx: Ctx = Depends(require("admin"))):
    config = {"require_signature": body.require_signature}
    if body.mode == "live" and body.provider == "n8n":
        if not body.base_url or not body.api_key:
            raise HTTPException(422, "n8n live mode needs base_url and api_key")
        try:
            check_url_safe(body.base_url)
        except ValueError as e:
            raise HTTPException(422, str(e))
        config["base_url"] = body.base_url
    if body.provider == "google_ads":
        config.update(customer_id=body.customer_id, login_customer_id=body.login_customer_id, allow_mutations=body.allow_mutations)
        if body.mode == "live" and not (settings.google_client_id and settings.google_ads_developer_token):
            raise HTTPException(422, "Google Ads OAuth client and developer token are not configured on the server")
    if body.provider == "outreach" and body.mode == "live":
        raise HTTPException(422, "Live outreach providers are post-MVP; use sandbox")
    key, key_hash, prefix = new_api_key("csi")
    signing_secret = secrets.token_hex(24)
    integ = Integration(organization_id=ctx.org.id, provider=body.provider, name=body.name, mode=body.mode, config=config,
                        ingest_key_hash=key_hash, ingest_key_prefix=prefix, signing_secret_enc=encrypt(signing_secret),
                        status="connected" if body.mode == "sandbox" or body.provider == "n8n" else "pending_authorization")
    integ.capabilities = connectors.capabilities(integ)
    ctx.db.add(integ)
    ctx.db.flush()
    if body.api_key:
        ctx.db.add(IntegrationCredential(integration_id=integ.id, ciphertext=encrypt(body.api_key), scope="n8n:api"))
        ctx.db.flush()
    if body.mode == "live" and body.provider == "n8n":
        try:  # validate connectivity before saving
            connectors.health(ctx.db, integ)
        except ProviderError as e:
            ctx.db.rollback()
            raise HTTPException(422, f"Could not connect to n8n: {e.detail}")
    audit(ctx.db, ctx.org.id, ctx.actor, "integration.created", f"integration:{integ.id}", {"provider": body.provider, "mode": body.mode})
    ctx.db.commit()
    return _integration_out(integ, ctx.db, ingest_key=key, signing_secret=signing_secret,
                            ingest_url=f"{settings.public_api_url}/v1/events")


@router.get("/integrations")
def list_integrations(ctx: Ctx = Depends(get_ctx)):
    rows = ctx.db.scalars(select(Integration).where(Integration.organization_id == ctx.org.id).order_by(Integration.created_at)).all()
    return [_integration_out(i, ctx.db) for i in rows]


@router.get("/integrations/{integration_id}")
def get_integration(integration_id: str, ctx: Ctx = Depends(get_ctx)):
    return _integration_out(owned(ctx.db, Integration, integration_id, ctx.org.id), ctx.db)


@router.delete("/integrations/{integration_id}")
def revoke_integration(integration_id: str, ctx: Ctx = Depends(require("admin"))):
    integ = owned(ctx.db, Integration, integration_id, ctx.org.id)
    integ.status, integ.ingest_key_hash = "revoked", None
    cred = ctx.db.scalar(select(IntegrationCredential).where(IntegrationCredential.integration_id == integ.id))
    if cred:
        ctx.db.delete(cred)
    audit(ctx.db, ctx.org.id, ctx.actor, "integration.revoked", f"integration:{integ.id}", {})
    ctx.db.commit()
    return {"ok": True}


@router.post("/integrations/{integration_id}/rotate-key")
def rotate_ingest_key(integration_id: str, ctx: Ctx = Depends(require("admin"))):
    integ = owned(ctx.db, Integration, integration_id, ctx.org.id)
    if integ.status == "revoked":
        raise HTTPException(409, "Integration is revoked")
    key, integ.ingest_key_hash, integ.ingest_key_prefix = new_api_key("csi")
    audit(ctx.db, ctx.org.id, ctx.actor, "integration.key_rotated", f"integration:{integ.id}", {})
    ctx.db.commit()
    return {"ingest_key": key}


class Simulate(BaseModel):
    outage: bool = False
    auth_expired: bool = False
    quota: bool = False


@router.post("/integrations/{integration_id}/simulate")
def simulate_faults(integration_id: str, body: Simulate, ctx: Ctx = Depends(require("admin"))):
    """Fault injection for sandbox integrations (staging / demos)."""
    integ = owned(ctx.db, Integration, integration_id, ctx.org.id)
    if integ.mode != "sandbox":
        raise HTTPException(409, "Fault injection is only available for sandbox integrations")
    integ.config = {**integ.config, "simulate": body.model_dump()}
    ctx.db.commit()
    return {"ok": True}


@router.post("/integrations/{integration_id}/check")
def check_integration(integration_id: str, ctx: Ctx = Depends(require("operator"))):
    integ = owned(ctx.db, Integration, integration_id, ctx.org.id)
    if integ.status == "revoked":
        raise HTTPException(409, "Integration is revoked")
    try:
        connectors.health(ctx.db, integ)
        summary = connectors.sync(ctx.db, ctx.org, integ)
        detection.record_health(ctx.db, ctx.org, integ, True)
        ok, detail = True, summary
    except ProviderError as e:
        ctx.db.rollback()
        detection.record_health(ctx.db, ctx.org, integ, False, e.detail, e.kind)
        ok, detail = False, {"error": e.kind, "detail": e.detail}
    ctx.db.commit()
    return {"ok": ok, "detail": detail, "integration": _integration_out(integ, ctx.db)}


@router.get("/integrations/{integration_id}/instrumentation")
def instrumentation(integration_id: str, ctx: Ctx = Depends(get_ctx)):
    """Importable n8n error-reporter workflow wired to this integration's ingest endpoint."""
    owned(ctx.db, Integration, integration_id, ctx.org.id)
    raw = (Path(__file__).parent.parent / "n8n_error_reporter.json").read_text()
    return json.loads(raw.replace("__INGEST_URL__", f"{settings.public_api_url}/v1/events"))


@router.get("/integrations/google-ads/oauth/start")
def google_oauth_start(integration_id: str, ctx: Ctx = Depends(require("admin"))):
    integ = owned(ctx.db, Integration, integration_id, ctx.org.id)
    nonce = secrets.token_urlsafe(16)
    state = f"{integ.id}.{nonce}.{sign(integ.id + nonce)}"
    integ.config = {**integ.config, "oauth_state": sha256(state), "oauth_state_exp": (utcnow() + timedelta(minutes=10)).isoformat()}
    ctx.db.commit()
    return {"url": "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
        "client_id": settings.google_client_id, "redirect_uri": f"{settings.public_api_url}/v1/integrations/google-ads/oauth/callback",
        "response_type": "code", "scope": "https://www.googleapis.com/auth/adwords", "access_type": "offline",
        "prompt": "consent", "state": state})}


@router.get("/integrations/google-ads/oauth/callback", include_in_schema=False)
def google_oauth_callback(state: str, code: str | None = None, error: str | None = None, db=Depends(get_db)):
    back = f"{settings.public_app_url}/integrations"
    try:
        integ_id, nonce, sig = state.split(".")
    except ValueError:
        raise HTTPException(400, "Invalid OAuth state")
    integ = db.get(Integration, integ_id)
    cfg = (integ.config or {}) if integ else {}
    if (not integ or sign(integ_id + nonce) != sig or cfg.get("oauth_state") != sha256(state)
            or cfg.get("oauth_state_exp", "") < utcnow().isoformat()):
        raise HTTPException(400, "Invalid or expired OAuth state")
    integ.config = {k: v for k, v in cfg.items() if not k.startswith("oauth_state")}  # single use
    if error or not code:
        db.commit()
        return RedirectResponse(f"{back}?oauth=denied")
    r = httpx.post("https://oauth2.googleapis.com/token", timeout=15, data={
        "code": code, "client_id": settings.google_client_id, "client_secret": settings.google_client_secret,
        "redirect_uri": f"{settings.public_api_url}/v1/integrations/google-ads/oauth/callback", "grant_type": "authorization_code"})
    if r.status_code != 200 or "refresh_token" not in r.json():
        db.commit()
        return RedirectResponse(f"{back}?oauth=failed")
    cred = db.scalar(select(IntegrationCredential).where(IntegrationCredential.integration_id == integ.id))
    if cred:
        cred.ciphertext = encrypt(r.json()["refresh_token"])
    else:
        db.add(IntegrationCredential(integration_id=integ.id, ciphertext=encrypt(r.json()["refresh_token"]), scope="adwords"))
    integ.status = "connected"
    audit(db, integ.organization_id, "oauth:google", "integration.authorized", f"integration:{integ.id}", {})
    db.commit()
    return RedirectResponse(f"{back}?oauth=connected")


# --- event ingestion --------------------------------------------------------

@router.post("/events", status_code=202, tags=["ingestion"])
async def ingest_events(
    request: Request, db=Depends(get_db), x_campaignshield_key: str | None = Header(None),
    x_cs_timestamp: str | None = Header(None), x_cs_signature: str | None = Header(None),
):
    """Authenticated ingestion. Body: a canonical event, `{"events": [...]}`, or `{"n8n": <execution>}`."""
    if not x_campaignshield_key:
        raise HTTPException(401, "Missing X-CampaignShield-Key")
    integ = db.scalar(select(Integration).where(Integration.ingest_key_hash == sha256(x_campaignshield_key)))
    if not integ or integ.status == "revoked":
        raise HTTPException(401, "Invalid ingest key")
    body = await request.body()
    if len(body) > 512_000:
        raise HTTPException(413, "Payload too large")
    if x_cs_signature or integ.config.get("require_signature"):
        if not (x_cs_timestamp and x_cs_signature and integ.signing_secret_enc
                and verify_webhook_signature(decrypt(integ.signing_secret_enc), x_cs_timestamp, body, x_cs_signature)):
            raise HTTPException(401, "Invalid or stale signature")
    rate_limit(f"ingest:{integ.organization_id}", settings.rate_limit_per_minute * 10)
    try:
        data = json.loads(body)
    except ValueError:
        raise HTTPException(400, "Body must be JSON")
    items = data.get("events") if isinstance(data, dict) and "events" in data else data if isinstance(data, list) else [data]
    if not isinstance(items, list) or len(items) > 500:
        raise HTTPException(422, "Send at most 500 events per request")
    org = db.get(Organization, integ.organization_id)
    return ingest(db, org, integ, items)


@router.get("/events", tags=["ingestion"])
def list_events(ctx: Ctx = Depends(get_ctx), event_type: str | None = None, resource_id: str | None = None,
                trace_id: str | None = None, integration_id: str | None = None,
                limit: int = Query(50, le=200), offset: int = 0):
    q = select(Event).where(Event.organization_id == ctx.org.id)
    for col, val in ((Event.event_type, event_type), (Event.resource_id, resource_id), (Event.trace_id, trace_id),
                     (Event.integration_id, integration_id)):
        if val:
            q = q.where(col == val)
    total, rows = _page(q.order_by(Event.occurred_at.desc()), limit, offset, ctx.db)
    return {"total": total, "items": [to_dict(e) for e in rows]}


@router.get("/events/quarantine", tags=["ingestion"])
def quarantine(ctx: Ctx = Depends(get_ctx), limit: int = Query(50, le=200)):
    rows = ctx.db.scalars(select(QuarantinedEvent).where(QuarantinedEvent.organization_id == ctx.org.id)
                          .order_by(QuarantinedEvent.received_at.desc()).limit(limit)).all()
    return [to_dict(r) for r in rows]


# --- workflows & campaigns --------------------------------------------------

def _wf_stats(db, wf: Workflow) -> dict:
    since = utcnow() - timedelta(hours=24)
    rows = db.execute(select(Event.event_type, func.count()).where(
        Event.organization_id == wf.organization_id, Event.resource_id == wf.external_id, Event.occurred_at >= since,
        Event.event_type.in_(["workflow.execution.succeeded", "workflow.execution.failed"])).group_by(Event.event_type)).all()
    counts = {t.rsplit(".", 1)[-1]: n for t, n in rows}
    total = sum(counts.values())
    ok = counts.get("succeeded", 0)
    return {"executions_24h": total, "failures_24h": counts.get("failed", 0), "success_rate_24h": round(ok / total * 100, 1) if total else None}


def _wf_health(wf: Workflow, stats: dict) -> str:
    if wf.status != "active":
        return "inactive"
    if wf.expected_interval_minutes and wf.last_execution_at and (utcnow() - wf.last_execution_at).total_seconds() > wf.expected_interval_minutes * 120:
        return "stalled"
    rate = stats["success_rate_24h"]
    return "unknown" if rate is None else "healthy" if rate >= 95 and wf.last_status != "failed" else "degraded" if rate >= 70 else "failing"


@router.get("/workflows")
def list_workflows(ctx: Ctx = Depends(get_ctx), integration_id: str | None = None):
    q = select(Workflow).where(Workflow.organization_id == ctx.org.id)
    if integration_id:
        q = q.where(Workflow.integration_id == integration_id)
    out = []
    for wf in ctx.db.scalars(q.order_by(Workflow.name)):
        stats = _wf_stats(ctx.db, wf)
        out.append(to_dict(wf, **stats, health=_wf_health(wf, stats)))
    return out


@router.get("/workflows/{workflow_id}")
def get_workflow(workflow_id: str, ctx: Ctx = Depends(get_ctx)):
    wf = owned(ctx.db, Workflow, workflow_id, ctx.org.id)
    stats = _wf_stats(ctx.db, wf)
    execs = ctx.db.scalars(select(Event).where(Event.organization_id == ctx.org.id, Event.resource_id == wf.external_id)
                           .order_by(Event.occurred_at.desc()).limit(50)).all()
    return to_dict(wf, **stats, health=_wf_health(wf, stats), recent_events=[to_dict(e) for e in execs])


class WorkflowUpdate(BaseModel):
    monitored: bool | None = None
    expected_interval_minutes: int | None = Field(None, ge=1, le=10080)


@router.patch("/workflows/{workflow_id}")
def update_workflow(workflow_id: str, body: WorkflowUpdate, ctx: Ctx = Depends(require("operator"))):
    wf = owned(ctx.db, Workflow, workflow_id, ctx.org.id)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(wf, k, v)
    audit(ctx.db, ctx.org.id, ctx.actor, "workflow.monitoring_updated", f"workflow:{wf.id}", body.model_dump(exclude_unset=True))
    ctx.db.commit()
    return to_dict(wf)


def _campaign_out(db, c: Campaign, hours: int = 48) -> dict:
    since = utcnow() - timedelta(hours=hours)
    series = db.execute(select(CampaignMetric.bucket_start, CampaignMetric.spend).where(
        CampaignMetric.campaign_id == c.id, CampaignMetric.bucket_start >= since).order_by(CampaignMetric.bucket_start)).all()
    day_start = datetime.now(ZoneInfo(c.timezone)).replace(hour=0, minute=0, second=0, microsecond=0)
    today = db.scalar(select(func.coalesce(func.sum(CampaignMetric.spend), 0)).where(
        CampaignMetric.campaign_id == c.id, CampaignMetric.bucket_start >= day_start))
    lag = (utcnow() - c.metrics_as_of).total_seconds() / 3600 if c.metrics_as_of else None
    return to_dict(c, spend_today=round(today, 2), series=[{"t": t.isoformat(), "spend": s} for t, s in series],
                   freshness={"metrics_as_of": c.metrics_as_of, "lag_hours": round(lag, 1) if lag is not None else None,
                              "label": "unknown" if lag is None else "fresh" if lag < 3 else "delayed" if lag < 12 else "stale"})


@router.get("/campaigns")
def list_campaigns(ctx: Ctx = Depends(get_ctx), integration_id: str | None = None):
    q = select(Campaign).where(Campaign.organization_id == ctx.org.id)
    if integration_id:
        q = q.where(Campaign.integration_id == integration_id)
    return [_campaign_out(ctx.db, c) for c in ctx.db.scalars(q.order_by(Campaign.name))]


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, ctx: Ctx = Depends(get_ctx)):
    c = owned(ctx.db, Campaign, campaign_id, ctx.org.id)
    actions = ctx.db.scalars(select(ActionRequest).where(ActionRequest.organization_id == ctx.org.id,
                                                         ActionRequest.target["campaign_id"].as_string().in_([c.id, c.external_id]))
                             .order_by(ActionRequest.created_at.desc()).limit(20)).all()
    return {**_campaign_out(ctx.db, c, 24 * 7), "actions": [to_dict(a) for a in actions]}


# --- agents -----------------------------------------------------------------

class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    allowed_actions: list[str] = Field(default_factory=list, max_length=50)


class AgentUpdate(BaseModel):
    status: str | None = Field(None, pattern="^(active|suspended)$")
    allowed_actions: list[str] | None = Field(None, max_length=50)


@router.get("/agents")
def list_agents(ctx: Ctx = Depends(get_ctx)):
    out = []
    for a in ctx.db.scalars(select(Agent).where(Agent.organization_id == ctx.org.id).order_by(Agent.created_at)):
        n = ctx.db.scalar(select(func.count()).select_from(ActionRequest).where(ActionRequest.agent_id == a.id))
        out.append(to_dict(a, actions_total=n))
    return out


@router.post("/agents", status_code=201)
def create_agent(body: AgentCreate, ctx: Ctx = Depends(require("admin"))):
    key, key_hash, prefix = new_api_key("csa")
    a = Agent(organization_id=ctx.org.id, name=body.name, key_hash=key_hash, key_prefix=prefix, allowed_actions=body.allowed_actions)
    ctx.db.add(a)
    ctx.db.flush()
    audit(ctx.db, ctx.org.id, ctx.actor, "agent.created", f"agent:{a.id}", {"allowed_actions": body.allowed_actions})
    ctx.db.commit()
    return to_dict(a, api_key=key)


@router.patch("/agents/{agent_id}")
def update_agent(agent_id: str, body: AgentUpdate, ctx: Ctx = Depends(require("admin"))):
    a = owned(ctx.db, Agent, agent_id, ctx.org.id)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(a, k, v)
    audit(ctx.db, ctx.org.id, ctx.actor, "agent.updated", f"agent:{a.id}", changes)
    ctx.db.commit()
    return to_dict(a)


@router.post("/agents/{agent_id}/rotate-key")
def rotate_agent_key(agent_id: str, ctx: Ctx = Depends(require("admin"))):
    a = owned(ctx.db, Agent, agent_id, ctx.org.id)
    key, a.key_hash, a.key_prefix = new_api_key("csa")
    audit(ctx.db, ctx.org.id, ctx.actor, "agent.key_rotated", f"agent:{a.id}", {})
    ctx.db.commit()
    return {"api_key": key}


# --- traces -----------------------------------------------------------------

@router.get("/traces/{trace_id}")
def get_trace(trace_id: str, ctx: Ctx = Depends(get_ctx)):
    events = ctx.db.scalars(select(Event).where(Event.organization_id == ctx.org.id, Event.trace_id == trace_id)
                            .order_by(Event.occurred_at)).all()
    actions = ctx.db.scalars(select(ActionRequest).where(ActionRequest.organization_id == ctx.org.id, ActionRequest.trace_id == trace_id)).all()
    decisions = ctx.db.scalars(select(PolicyDecision).where(PolicyDecision.organization_id == ctx.org.id, PolicyDecision.trace_id == trace_id)).all()
    if not (events or actions):
        raise HTTPException(404, "Trace not found")
    status = "failed" if any(e.event_type.endswith("failed") for e in events) else \
        "blocked" if any(a.status == "denied" for a in actions) else "ok"
    return {"trace_id": trace_id, "status": status, "events": [to_dict(e) for e in events],
            "actions": [to_dict(a) for a in actions], "decisions": [to_dict(d) for d in decisions]}
