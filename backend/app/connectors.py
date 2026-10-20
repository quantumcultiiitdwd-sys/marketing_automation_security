"""Provider connectors. `sandbox` mode keeps provider state in our DB (demo/staging); `live` calls the real API."""

import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select

from .config import settings
from .core import emit
from .db import utcnow
from .models import Campaign, CampaignMetric, Event, Integration, IntegrationCredential, Organization, Workflow
from .security import check_url_safe, decrypt


class ProviderError(Exception):
    def __init__(self, kind: str, detail: str = ""):
        super().__init__(detail or kind)
        self.kind = kind  # timeout | auth | quota | unavailable | invalid | unsupported
        self.detail = detail or kind


ACTIONS = {
    # action_type: provider, resource, risk, reversibility
    "ads.campaign.update_budget": {"provider": "google_ads", "resource": "campaign", "risk": "high", "reversible": "reversible"},
    "ads.campaign.pause": {"provider": "google_ads", "resource": "campaign", "risk": "medium", "reversible": "reversible"},
    "ads.campaign.enable": {"provider": "google_ads", "resource": "campaign", "risk": "high", "reversible": "reversible"},
    "n8n.workflow.activate": {"provider": "n8n", "resource": "workflow", "risk": "medium", "reversible": "reversible"},
    "n8n.workflow.deactivate": {"provider": "n8n", "resource": "workflow", "risk": "medium", "reversible": "reversible"},
    "n8n.workflow.rollback": {"provider": "n8n", "resource": "workflow", "risk": "medium", "reversible": "reversible"},
    "outreach.email.send": {"provider": "outreach", "resource": None, "risk": "high", "reversible": "irreversible"},
    "cs.agent.suspend": {"provider": "internal", "resource": "agent", "risk": "medium", "reversible": "reversible"},
}


def capabilities(integ: Integration) -> dict:
    live = integ.mode == "live"
    if integ.provider == "n8n":
        actions = ["n8n.workflow.activate", "n8n.workflow.deactivate"] + ([] if live else ["n8n.workflow.rollback"])
        return {"monitoring": ["workflows", "executions", "heartbeat", "config_drift"], "actions": actions,
                "enforcement": "gateway", "notes": "Only actions routed through the CampaignShield gateway can be blocked."}
    if integ.provider == "google_ads":
        mutations = not live or bool(integ.config.get("allow_mutations"))
        return {"monitoring": ["campaigns", "budgets", "hourly_spend", "status_changes"],
                "actions": ["ads.campaign.update_budget", "ads.campaign.pause", "ads.campaign.enable"] if mutations else [],
                "enforcement": "gateway" if mutations else "observe_only",
                "notes": "Metrics can be delayed by the provider; spend alerts are not real-time prevention."}
    if integ.provider == "outreach":
        return {"monitoring": ["deliveries"], "actions": ["outreach.email.send"], "enforcement": "gateway",
                "notes": "Delivered email cannot be recalled."}
    return {"monitoring": [], "actions": [], "enforcement": "none"}


def _credential(db, integ: Integration) -> str:
    cred = db.scalar(select(IntegrationCredential).where(IntegrationCredential.integration_id == integ.id))
    if not cred:
        raise ProviderError("auth", "No credential stored")
    return decrypt(cred.ciphertext)


def _simulated_faults(integ: Integration):
    sim = (integ.config or {}).get("simulate", {})
    if sim.get("auth_expired"):
        raise ProviderError("auth", "Simulated: credential expired")
    if sim.get("quota"):
        raise ProviderError("quota", "Simulated: API quota exhausted")
    if sim.get("outage"):
        raise ProviderError("unavailable", "Simulated: provider unreachable")


def _http(method: str, url: str, **kw) -> httpx.Response:
    try:
        r = httpx.request(method, url, timeout=15, follow_redirects=False, **kw)
    except httpx.TimeoutException as e:
        raise ProviderError("timeout", str(e))
    except httpx.HTTPError as e:
        raise ProviderError("unavailable", str(e))
    if r.status_code in (401, 403):
        raise ProviderError("auth", f"HTTP {r.status_code}")
    if r.status_code == 429 or "RESOURCE_EXHAUSTED" in r.text[:2000]:
        raise ProviderError("quota", "Provider rate limit or quota exceeded")
    if r.status_code >= 500:
        raise ProviderError("unavailable", f"HTTP {r.status_code}")
    if r.status_code >= 400:
        raise ProviderError("invalid", f"HTTP {r.status_code}: {r.text[:300]}")
    return r


# --- n8n ------------------------------------------------------------------

def _n8n(db, integ: Integration, method: str, path: str, **kw) -> dict:
    base = check_url_safe(integ.config["base_url"]).rstrip("/")
    return _http(method, f"{base}/api/v1{path}", headers={"X-N8N-API-KEY": _credential(db, integ), "Accept": "application/json"}, **kw).json()


def _n8n_sync(db, org, integ: Integration) -> dict:
    from .ingestion import ingest

    found, cursor = 0, None
    for _ in range(10):
        page = _n8n(db, integ, "GET", "/workflows", params={"limit": 100, **({"cursor": cursor} if cursor else {})})
        for w in page.get("data", []):
            found += 1
            wf = db.scalar(select(Workflow).where(Workflow.integration_id == integ.id, Workflow.external_id == str(w["id"])))
            version = str(w.get("versionId") or w.get("updatedAt") or "1")
            if not wf:
                wf = Workflow(organization_id=org.id, integration_id=integ.id, external_id=str(w["id"]), version=version)
                db.add(wf)
            elif wf.version != version:  # configuration drift
                emit(db, org.id, "workflow.config.changed", resource_type="workflow", resource_id=wf.external_id,
                     integration_id=integ.id, severity="low", payload={"from_version": wf.version, "to_version": version})
                wf.version = version
            wf.name = w.get("name") or wf.name
            wf.status = "active" if w.get("active") else "inactive"
        cursor = page.get("nextCursor")
        if not cursor:
            break
    last_id = int(integ.config.get("last_execution_id") or 0)
    execs = _n8n(db, integ, "GET", "/executions", params={"limit": 100}).get("data", [])
    new = [e for e in execs if int(e["id"]) > last_id and e.get("status") not in ("running", "waiting", "new")]
    result = ingest(db, org, integ, [{"n8n": e} for e in sorted(new, key=lambda e: int(e["id"]))])
    if new:
        integ.config = {**integ.config, "last_execution_id": max(int(e["id"]) for e in new)}
    return {"workflows": found, "executions": result}


# --- Google Ads -----------------------------------------------------------

_token_cache: dict[str, tuple[str, float]] = {}


def _gads_token(db, integ: Integration) -> str:
    tok, exp = _token_cache.get(integ.id, ("", 0))
    if tok and exp > time.time() + 60:
        return tok
    try:
        r = httpx.post("https://oauth2.googleapis.com/token", timeout=15, data={
            "grant_type": "refresh_token", "refresh_token": _credential(db, integ),
            "client_id": settings.google_client_id, "client_secret": settings.google_client_secret})
    except httpx.HTTPError as e:
        raise ProviderError("unavailable", str(e))
    if r.status_code != 200:
        raise ProviderError("auth", "Google authorization expired or was revoked")
    body = r.json()
    _token_cache[integ.id] = (body["access_token"], time.time() + body.get("expires_in", 3600))
    return body["access_token"]


def _gads(db, integ: Integration, path: str, body: dict) -> dict:
    cid = integ.config["customer_id"].replace("-", "")
    headers = {"Authorization": f"Bearer {_gads_token(db, integ)}", "developer-token": settings.google_ads_developer_token}
    if integ.config.get("login_customer_id"):
        headers["login-customer-id"] = integ.config["login_customer_id"].replace("-", "")
    url = f"https://googleads.googleapis.com/{settings.google_ads_api_version}/customers/{cid}/{path}"
    return _http("POST", url, headers=headers, json=body).json()


def _gads_search(db, integ, query: str) -> list[dict]:
    rows, token = [], None
    for _ in range(20):
        page = _gads(db, integ, "googleAds:search", {"query": query, **({"pageToken": token} if token else {})})
        rows += page.get("results", [])
        token = page.get("nextPageToken")
        if not token:
            break
    return rows


def _gads_sync(db, org, integ: Integration) -> dict:
    from .detection import check_spend

    rows = _gads_search(db, integ, "SELECT campaign.id, campaign.name, campaign.status, campaign_budget.amount_micros, "
                                   "campaign_budget.resource_name, customer.currency_code, customer.time_zone FROM campaign "
                                   "WHERE campaign.status != 'REMOVED'")
    by_ext = {}
    for r in rows:
        c, b, cust = r["campaign"], r.get("campaignBudget", {}), r.get("customer", {})
        camp = db.scalar(select(Campaign).where(Campaign.integration_id == integ.id, Campaign.external_id == str(c["id"])))
        budget = int(b.get("amountMicros", 0)) / 1e6
        if not camp:
            camp = Campaign(organization_id=org.id, integration_id=integ.id, external_id=str(c["id"]), name=c["name"], daily_budget=budget)
            db.add(camp)
            db.flush()
        elif abs(camp.daily_budget - budget) > 0.005:  # change made outside the gateway (observe-only detection)
            emit(db, org.id, "campaign.budget.changed", resource_type="campaign", resource_id=camp.id, integration_id=integ.id,
                 severity="low", payload={"from": camp.daily_budget, "to": budget, "observed_via": "sync"})
        if camp.status != c["status"].lower() and camp.last_synced_at:
            emit(db, org.id, "campaign.status.changed", resource_type="campaign", resource_id=camp.id, integration_id=integ.id,
                 payload={"from": camp.status, "to": c["status"].lower()})
        camp.name, camp.status, camp.daily_budget = c["name"], c["status"].lower(), budget
        camp.currency, camp.timezone = cust.get("currencyCode", camp.currency), cust.get("timeZone", camp.timezone)
        camp.budget_resource, camp.last_synced_at = b.get("resourceName"), utcnow()
        by_ext[str(c["id"])] = camp
    start = (utcnow() - timedelta(days=2)).date().isoformat()
    gaql = ("SELECT campaign.id, segments.date, segments.hour, metrics.cost_micros, metrics.impressions, "
            f"metrics.clicks, metrics.conversions FROM campaign WHERE segments.date >= '{start}'")
    metrics = _gads_search(db, integ, gaql)
    changed = 0
    for r in metrics:
        camp = by_ext.get(str(r["campaign"]["id"]))
        if not camp:
            continue
        seg, m = r["segments"], r.get("metrics", {})
        bucket = datetime.fromisoformat(seg["date"]).replace(hour=int(seg["hour"]), tzinfo=ZoneInfo(camp.timezone)).astimezone(ZoneInfo("UTC"))
        changed += _upsert_metric(db, org, camp, bucket, int(m.get("costMicros", 0)) / 1e6, int(m.get("impressions", 0)),
                                  int(m.get("clicks", 0)), float(m.get("conversions", 0)), check_spend)
    return {"campaigns": len(by_ext), "metric_buckets_changed": changed}


def _upsert_metric(db, org, camp, bucket, spend, impressions, clicks, conversions, check) -> int:
    row = db.scalar(select(CampaignMetric).where(CampaignMetric.campaign_id == camp.id, CampaignMetric.bucket_start == bucket))
    if row and abs(row.spend - spend) < 0.005 and row.impressions == impressions:
        return 0
    if not row:
        row = CampaignMetric(organization_id=org.id, campaign_id=camp.id, bucket_start=bucket)
        db.add(row)
    row.spend, row.impressions, row.clicks, row.conversions, row.received_at = spend, impressions, clicks, conversions, utcnow()
    db.flush()
    if not camp.metrics_as_of or bucket > camp.metrics_as_of:
        camp.metrics_as_of = bucket
    check(db, org, camp, row)
    return 1


def record_metric(db, org, camp: Campaign, bucket: datetime, spend: float, impressions=0, clicks=0, conversions=0.0) -> int:
    from .detection import check_spend

    return _upsert_metric(db, org, camp, bucket, spend, impressions, clicks, conversions, check_spend)


# --- dispatch -------------------------------------------------------------

def health(db, integ: Integration) -> None:
    _simulated_faults(integ)
    if integ.mode != "live":
        return
    if integ.provider == "n8n":
        _n8n(db, integ, "GET", "/workflows", params={"limit": 1})
    elif integ.provider == "google_ads":
        _gads_search(db, integ, "SELECT customer.id FROM customer LIMIT 1")


def sync(db, org, integ: Integration) -> dict:
    _simulated_faults(integ)
    if integ.mode != "live":
        return {"mode": "sandbox", "note": "Sandbox telemetry arrives via the ingestion API or demo scenarios"}
    if integ.provider == "n8n":
        return _n8n_sync(db, org, integ)
    if integ.provider == "google_ads":
        if not integ.config.get("customer_id"):
            raise ProviderError("invalid", "Google Ads customer ID not configured")
        return _gads_sync(db, org, integ)
    return {}


def read_state(db, integ: Integration | None, action_type: str, res, action_id: str | None = None) -> dict:
    if action_type.startswith("ads."):
        if integ.mode == "live" and res.budget_resource:
            _gads_sync(db, db.get(Organization, integ.organization_id), integ)
        return {"daily_budget": res.daily_budget, "status": res.status, "currency": res.currency}
    if action_type.startswith("n8n."):
        if integ.mode == "live":
            w = _n8n(db, integ, "GET", f"/workflows/{res.external_id}")
            res.status = "active" if w.get("active") else "inactive"
        return {"status": res.status, "version": res.version}
    if action_type == "outreach.email.send":
        delivered = db.scalar(select(Event.id).where(Event.event_type == "provider.outreach.sent",
                                                     Event.correlation_id == action_id)) if action_id else None
        return {"delivered": bool(delivered)}
    if action_type == "cs.agent.suspend":
        return {"status": res.status}
    return {}


def execute(db, integ: Integration | None, action_type: str, res, params: dict, action_id: str, trace_id: str) -> tuple[dict, dict]:
    """Perform the downstream mutation. Returns (prior_state, result)."""
    if integ:
        _simulated_faults(integ)
        if action_type not in capabilities(integ)["actions"]:
            raise ProviderError("unsupported", f"{action_type} is not enabled for this integration")
    prior = read_state(db, integ, action_type, res, action_id)
    live = integ is not None and integ.mode == "live"

    if action_type == "ads.campaign.update_budget":
        new = float(params["proposed_daily_budget"])
        if live:
            _gads(db, integ, "campaignBudgets:mutate", {"operations": [{"update": {"resourceName": res.budget_resource,
                  "amountMicros": str(int(round(new * 1e6)))}, "updateMask": "amount_micros"}]})
        res.daily_budget = new
        return prior, {"daily_budget": new}
    if action_type in ("ads.campaign.pause", "ads.campaign.enable"):
        status = "paused" if action_type.endswith("pause") else "enabled"
        if live:
            cid = integ.config["customer_id"].replace("-", "")
            _gads(db, integ, "campaigns:mutate", {"operations": [{"update": {"resourceName": f"customers/{cid}/campaigns/{res.external_id}",
                  "status": status.upper()}, "updateMask": "status"}]})
        res.status = status
        return prior, {"status": status}
    if action_type in ("n8n.workflow.activate", "n8n.workflow.deactivate"):
        verb = action_type.rsplit(".", 1)[-1]
        if live:
            _n8n(db, integ, "POST", f"/workflows/{res.external_id}/{verb}")
        res.status = "active" if verb == "activate" else "inactive"
        return prior, {"status": res.status}
    if action_type == "n8n.workflow.rollback":
        if not res.previous_config:
            raise ProviderError("invalid", "No previous configuration to roll back to")
        res.config, res.previous_config = res.previous_config, res.config
        res.version = str(int(res.version) + 1) if res.version.isdigit() else res.version + "+rollback"
        emit(db, res.organization_id, "workflow.config.changed", resource_type="workflow", resource_id=res.external_id,
             integration_id=integ.id, trace_id=trace_id, payload={"to_version": res.version, "reason": "rollback"})
        return prior, {"version": res.version, "config": res.config}
    if action_type == "outreach.email.send":
        count = len(params.get("recipients", []))
        emit(db, integ.organization_id, "provider.outreach.sent", source="outreach", trace_id=trace_id, resource_type="outreach",
             resource_id=params.get("campaign"), integration_id=integ.id,
             correlation_id=action_id, payload={"action_id": action_id, "recipient_count": count, "subject": params.get("subject")})
        if params.get("simulate_timeout"):  # delivered, but the response is lost — the classic duplicate-send trap
            raise ProviderError("timeout", "Simulated downstream timeout after delivery")
        return prior, {"delivered": True, "recipient_count": count}
    if action_type == "cs.agent.suspend":
        res.status = "suspended"
        return prior, {"status": "suspended"}
    raise ProviderError("unsupported", action_type)
