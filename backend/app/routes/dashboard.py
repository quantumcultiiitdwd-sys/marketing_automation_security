from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, update

from .. import demo
from ..config import settings
from ..core import verify_audit_chain
from ..db import utcnow
from ..deps import Ctx, get_ctx, require
from ..models import (ActionRequest, Alert, AuditRecord, Campaign, Event, Incident, Integration, Notification, PolicyDecision,
                      Workflow, to_dict)
from .resources import _wf_health, _wf_stats

router = APIRouter(prefix="/v1", tags=["dashboard"])
ACTIVE = ["open", "investigating", "awaiting_approval", "mitigating"]


@router.get("/dashboard/summary")
def summary(ctx: Ctx = Depends(get_ctx), days: int = Query(7, ge=1, le=90), integration_id: str | None = None):
    db, org = ctx.db, ctx.org.id
    since = utcnow() - timedelta(days=days)
    integs = db.scalars(select(Integration).where(Integration.organization_id == org, Integration.status != "revoked")).all()
    wq = select(Workflow).where(Workflow.organization_id == org, Workflow.monitored.is_(True))
    iq = select(Incident).where(Incident.organization_id == org)
    if integration_id:
        wq, iq = wq.where(Workflow.integration_id == integration_id), iq.where(Incident.integration_id == integration_id)
    workflows = db.scalars(wq).all()
    health = {}
    for wf in workflows:
        h = _wf_health(wf, _wf_stats(db, wf))
        health[h] = health.get(h, 0) + 1
    open_inc = db.scalars(iq.where(Incident.status.in_(ACTIVE)).order_by(Incident.last_seen_at.desc())).all()
    sev = {s: sum(i.severity == s for i in open_inc) for s in ("critical", "high", "medium", "low")}
    violations = db.scalars(select(PolicyDecision).where(PolicyDecision.organization_id == org, PolicyDecision.dry_run.is_(False),
                                                         PolicyDecision.decision.in_(["DENY", "REQUIRE_APPROVAL"]), PolicyDecision.created_at >= since)
                            .order_by(PolicyDecision.created_at.desc())).all()
    prevented = db.scalar(select(func.count()).select_from(ActionRequest).where(
        ActionRequest.organization_id == org, ActionRequest.status.in_(["denied", "rejected"]), ActionRequest.created_at >= since))
    dupes = db.scalar(select(func.count()).select_from(Event).where(
        Event.organization_id == org, Event.event_type == "action.duplicate_suppressed", Event.occurred_at >= since))
    executed = db.scalar(select(func.count()).select_from(ActionRequest).where(
        ActionRequest.organization_id == org, ActionRequest.status == "executed", ActionRequest.created_at >= since))
    critical_alerts = db.scalars(select(Alert).where(Alert.organization_id == org, Alert.severity.in_(["critical", "high"]),
                                                     Alert.created_at >= since).order_by(Alert.created_at.desc()).limit(5)).all()
    trace_rows = db.execute(select(Event.trace_id, func.max(Event.occurred_at), func.count()).where(
        Event.organization_id == org, Event.trace_id.is_not(None), Event.occurred_at >= since)
        .group_by(Event.trace_id).order_by(func.max(Event.occurred_at).desc()).limit(8)).all()
    traces = []
    for tid, last, n in trace_rows:
        types = db.scalars(select(Event.event_type).where(Event.organization_id == org, Event.trace_id == tid)).all()
        status = "blocked" if "policy.decision" in types and "action.executed" not in types and "action.requested" in types else \
            "failed" if any(t.endswith("failed") for t in types) else "ok"
        traces.append({"trace_id": tid, "last_event_at": last, "events": n, "status": status, "root": types[0] if types else None})
    spend = [i for i in open_inc if i.kind == "spend_anomaly"]
    return {
        "organization": {"id": ctx.org.id, "name": ctx.org.name, "kill_switch": bool((ctx.org.settings or {}).get("kill_switch"))},
        "window_days": days,
        "integrations": {"total": len(integs), "connected": sum(i.status == "connected" for i in integs),
                         "items": [{"id": i.id, "name": i.name, "provider": i.provider, "mode": i.mode, "status": i.status,
                                    "enforcement": (i.capabilities or {}).get("enforcement"), "last_check_at": (i.health or {}).get("last_check_at"),
                                    "last_error": (i.health or {}).get("last_error")} for i in integs]},
        "workflows": {"monitored": len(workflows), "health": health},
        "campaigns": {"monitored": db.scalar(select(func.count()).select_from(Campaign).where(Campaign.organization_id == org))},
        "incidents": {"open": len(open_inc), "by_severity": sev,
                      "recent": [to_dict(i, rca=None) for i in open_inc[:6]]},
        "critical_alerts": [to_dict(a) for a in critical_alerts],
        "policy_violations": {"count": len(violations), "recent": [to_dict(v) for v in violations[:6]]},
        "protection": {"actions_blocked": prevented, "duplicates_suppressed": dupes, "actions_executed": executed,
                       "pending_approvals": db.scalar(select(func.count()).select_from(ActionRequest).where(
                           ActionRequest.organization_id == org, ActionRequest.status == "pending_approval"))},
        "spend_anomalies": [to_dict(i, rca=None) for i in spend],
        "recent_traces": traces,
        "generated_at": utcnow(),
    }


@router.get("/audit")
def audit_log(ctx: Ctx = Depends(require("analyst")), action: str | None = None, limit: int = Query(100, le=500), offset: int = 0):
    q = select(AuditRecord).where(AuditRecord.organization_id == ctx.org.id)
    if action:
        q = q.where(AuditRecord.action.like(f"{action}%"))
    total = ctx.db.scalar(select(func.count()).select_from(q.subquery()))
    rows = ctx.db.scalars(q.order_by(AuditRecord.seq.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [to_dict(r) for r in rows]}


@router.get("/audit/verify")
def audit_verify(ctx: Ctx = Depends(require("analyst"))):
    return verify_audit_chain(ctx.db, ctx.org.id)


@router.get("/notifications")
def notifications(ctx: Ctx = Depends(get_ctx)):
    rows = ctx.db.scalars(select(Notification).where(Notification.organization_id == ctx.org.id)
                          .order_by(Notification.created_at.desc()).limit(30)).all()
    return [to_dict(n) for n in rows]


@router.post("/notifications/read")
def mark_read(ctx: Ctx = Depends(get_ctx)):
    ctx.db.execute(update(Notification).where(Notification.organization_id == ctx.org.id).values(read=True))
    ctx.db.commit()
    return {"ok": True}


@router.get("/demo/scenarios")
def scenarios(ctx: Ctx = Depends(get_ctx)):
    return {"enabled": settings.demo_enabled, "scenarios": demo.SCENARIOS}


@router.post("/demo/seed")
def seed(ctx: Ctx = Depends(require("admin"))):
    if not settings.demo_enabled:
        raise HTTPException(404, "Demo mode disabled")
    return demo.seed(ctx.db, ctx.org, ctx.actor)


@router.post("/demo/scenarios/{name}")
def run_scenario(name: str, ctx: Ctx = Depends(require("admin"))):
    if not settings.demo_enabled:
        raise HTTPException(404, "Demo mode disabled")
    result = demo.run(ctx.db, ctx.org, name, ctx.actor)
    ctx.db.commit()
    return result
