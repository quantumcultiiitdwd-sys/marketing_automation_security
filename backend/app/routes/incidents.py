from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm.exc import StaleDataError

from .. import remediation
from ..core import audit, notify
from ..db import utcnow
from ..deps import Ctx, get_ctx, owned, require
from ..incidents import SEVERITIES, STATUSES, _activity, transition
from ..models import (ActionRequest, Approval, Incident, IncidentActivity, IncidentEvidence, Membership, PolicyDecision, Remediation,
                      User, to_dict)
from ..rca import investigate

router = APIRouter(prefix="/v1", tags=["incidents & remediation"])


@router.get("/incidents")
def list_incidents(ctx: Ctx = Depends(get_ctx), status: str | None = None, severity: str | None = None, kind: str | None = None,
                   integration_id: str | None = None, active: bool = False, limit: int = Query(100, le=500), offset: int = 0):
    q = select(Incident).where(Incident.organization_id == ctx.org.id)
    for col, val in ((Incident.status, status), (Incident.severity, severity), (Incident.kind, kind), (Incident.integration_id, integration_id)):
        if val:
            q = q.where(col == val)
    if active:
        q = q.where(Incident.status.in_(["open", "investigating", "awaiting_approval", "mitigating"]))
    rows = ctx.db.scalars(q.order_by(Incident.last_seen_at.desc()).limit(limit).offset(offset)).all()
    return [to_dict(i, rca=None, summary=(i.rca or {}).get("summary"),
                    top_cause=((i.rca or {}).get("hypotheses") or [{}])[0].get("cause")) for i in rows]


def _detail(ctx: Ctx, inc: Incident) -> dict:
    db = ctx.db
    evidence = db.scalars(select(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id).order_by(IncidentEvidence.created_at)).all()
    activity = db.scalars(select(IncidentActivity).where(IncidentActivity.incident_id == inc.id).order_by(IncidentActivity.created_at)).all()
    rems = db.scalars(select(Remediation).where(Remediation.incident_id == inc.id).order_by(Remediation.step)).all()
    action_ids = {e.data.get("action_id") or e.data.get("original_action_id") for e in evidence} - {None}
    action_ids |= {r.action_id for r in rems if r.action_id}
    actions = db.scalars(select(ActionRequest).where(ActionRequest.id.in_(action_ids))).all() if action_ids else []
    decisions = db.scalars(select(PolicyDecision).where(PolicyDecision.action_id.in_(action_ids))).all() if action_ids else []
    approvals = db.scalars(select(Approval).where(Approval.incident_id == inc.id)).all()
    assignee = db.get(User, inc.assignee_id) if inc.assignee_id else None
    return to_dict(inc, assignee_email=assignee.email if assignee else None,
                   evidence=[to_dict(e) for e in evidence if e.evidence_type != "event"],
                   activity=[to_dict(a) for a in activity], remediations=[to_dict(r) for r in rems],
                   actions=[to_dict(a) for a in actions], decisions=[to_dict(d) for d in decisions],
                   approvals=[to_dict(a) for a in approvals])


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, ctx: Ctx = Depends(get_ctx)):
    return _detail(ctx, owned(ctx.db, Incident, incident_id, ctx.org.id))


class IncidentPatch(BaseModel):
    status: str | None = None
    severity: str | None = None
    assignee_id: str | None = None
    note: str | None = Field(None, max_length=2000)
    version: int | None = None  # optimistic concurrency


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: str, body: IncidentPatch, ctx: Ctx = Depends(require("operator"))):
    inc = owned(ctx.db, Incident, incident_id, ctx.org.id)
    if body.version is not None and body.version != inc.version:
        raise HTTPException(409, "Incident was modified by someone else; reload and retry")
    if body.status:
        if body.status not in STATUSES:
            raise HTTPException(422, "Invalid status")
        transition(ctx.db, inc, body.status, ctx.actor, body.note)
    if body.severity and body.severity != inc.severity:
        if body.severity not in SEVERITIES:
            raise HTTPException(422, "Invalid severity")
        _activity(ctx.db, inc, ctx.actor, "system", {"message": f"Severity {inc.severity} → {body.severity}"})
        inc.severity = body.severity
    if body.assignee_id is not None:
        if body.assignee_id and not ctx.db.scalar(select(Membership.id).where(Membership.organization_id == ctx.org.id,
                                                                            Membership.user_id == body.assignee_id)):
            raise HTTPException(422, "Assignee is not a member of this organization")
        inc.assignee_id = body.assignee_id or None
        _activity(ctx.db, inc, ctx.actor, "assign", {"assignee_id": inc.assignee_id})
    try:
        ctx.db.commit()
    except StaleDataError:
        ctx.db.rollback()
        raise HTTPException(409, "Incident was modified concurrently; reload and retry")
    return _detail(ctx, inc)


class Comment(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


@router.post("/incidents/{incident_id}/comments", status_code=201)
def comment(incident_id: str, body: Comment, ctx: Ctx = Depends(require("analyst"))):
    inc = owned(ctx.db, Incident, incident_id, ctx.org.id)
    _activity(ctx.db, inc, ctx.actor, "comment", {"text": body.body})
    ctx.db.commit()
    return {"ok": True}


@router.post("/incidents/{incident_id}/acknowledge")
def acknowledge(incident_id: str, ctx: Ctx = Depends(require("operator"))):
    inc = owned(ctx.db, Incident, incident_id, ctx.org.id)
    if inc.status == "open":
        transition(ctx.db, inc, "investigating", ctx.actor, "Acknowledged")
    if not inc.assignee_id:
        inc.assignee_id = ctx.user.id
    ctx.db.commit()
    return _detail(ctx, inc)


@router.post("/incidents/{incident_id}/escalate")
def escalate(incident_id: str, ctx: Ctx = Depends(require("operator"))):
    inc = owned(ctx.db, Incident, incident_id, ctx.org.id)
    idx = SEVERITIES.index(inc.severity)
    inc.severity = SEVERITIES[min(idx + 1, len(SEVERITIES) - 1)]
    _activity(ctx.db, inc, ctx.actor, "system", {"message": f"Escalated to {inc.severity}"})
    notify(ctx.db, ctx.org, f"Escalated: {inc.title}", f"Severity now {inc.severity}", inc.severity, f"/incidents/{inc.id}")
    ctx.db.commit()
    return _detail(ctx, inc)


@router.post("/incidents/{incident_id}/investigate")
def reinvestigate(incident_id: str, ctx: Ctx = Depends(require("analyst"))):
    inc = owned(ctx.db, Incident, incident_id, ctx.org.id)
    investigate(ctx.db, inc)
    ctx.db.commit()
    return inc.rca


class Feedback(BaseModel):
    rank: int = Field(ge=1)
    verdict: str = Field(pattern="^(confirmed|rejected)$")
    note: str | None = Field(None, max_length=2000)


@router.post("/incidents/{incident_id}/feedback")
def feedback(incident_id: str, body: Feedback, ctx: Ctx = Depends(require("analyst"))):
    """Human verification of a hypothesis. Only confirmed hypotheses are ever shown as verified."""
    inc = owned(ctx.db, Incident, incident_id, ctx.org.id)
    rca = dict(inc.rca or {})
    hyps = [dict(h) for h in rca.get("hypotheses", [])]
    h = next((h for h in hyps if h["rank"] == body.rank), None)
    if not h:
        raise HTTPException(404, "Hypothesis not found")
    h["verified"] = body.verdict == "confirmed"
    h["feedback"] = {"verdict": body.verdict, "by": ctx.user.email, "at": utcnow().isoformat(), "note": body.note}
    rca["hypotheses"] = hyps
    rca["feedback"] = [*rca.get("feedback", []), {"rank": body.rank, "cause": h["cause"], **h["feedback"]}]
    inc.rca = rca
    _activity(ctx.db, inc, ctx.actor, "feedback", {"cause": h["cause"], "verdict": body.verdict, "note": body.note})
    ctx.db.commit()
    return rca


class Mute(BaseModel):
    minutes: int = Field(60, ge=5, le=10080)


@router.post("/incidents/{incident_id}/mute")
def mute(incident_id: str, body: Mute, ctx: Ctx = Depends(require("operator"))):
    """Suppression window: new alerts with this incident's dedup key are recorded but don't open incidents."""
    inc = owned(ctx.db, Incident, incident_id, ctx.org.id)
    until = (utcnow() + timedelta(minutes=body.minutes)).isoformat()
    s = dict(ctx.org.settings or {})
    s["suppressions"] = [x for x in s.get("suppressions", []) if x["until"] > utcnow().isoformat()] + [{"prefix": inc.dedup_key, "until": until}]
    ctx.org.settings = s
    audit(ctx.db, ctx.org.id, ctx.actor, "alerts.suppressed", f"incident:{inc.id}", {"until": until})
    ctx.db.commit()
    return {"suppressed_until": until}


@router.get("/incidents/{incident_id}/report", response_class=PlainTextResponse)
def report(incident_id: str, ctx: Ctx = Depends(get_ctx)):
    d = _detail(ctx, owned(ctx.db, Incident, incident_id, ctx.org.id))
    rca = d.get("rca") or {}
    lines = [f"# Incident report: {d['title']}", "",
             f"- **ID:** {d['id']}", f"- **Severity:** {d['severity']}", f"- **Status:** {d['status']}",
             f"- **Detected:** {d['detected_at']:%Y-%m-%d %H:%M:%S} UTC", f"- **Occurrences:** {d['occurrence_count']}",
             f"- **Resolved:** {d['resolved_at']:%Y-%m-%d %H:%M:%S} UTC" if d["resolved_at"] else "- **Resolved:** —",
             f"- **Resolution:** {d['resolution'] or '—'}", "", "## Summary", "", rca.get("summary", "—"), "",
             "## Timeline (observed facts)", ""]
    lines += [f"- `{t['at'][:19]}` **{t['type']}** — {t['description']}" for t in rca.get("timeline", [])] or ["- No events"]
    lines += ["", "## Hypotheses (inferred — heuristic confidence)", ""]
    for h in rca.get("hypotheses", []):
        lines.append(f"{h['rank']}. **{h['cause']}** — {h['confidence_label']} confidence, "
                     f"{'VERIFIED by ' + h['feedback']['by'] if h['verified'] else 'unverified'}. {h['explanation']}")
        if h["missing_evidence"]:
            lines.append(f"   - Missing evidence: {'; '.join(h['missing_evidence'])}")
    lines += ["", "## Blast radius", ""] + [f"- {k.replace('_', ' ')}: {v}" for k, v in (rca.get("blast_radius") or {}).items()]
    lines += ["", "## Policy decisions", ""] + ([f"- {x['created_at']:%H:%M:%S} {x['decision']} — " + "; ".join(r["message"] for r in x["reasons"])
                                                 for x in d["decisions"]] or ["- None"])
    lines += ["", "## Remediation", ""] + ([f"- [{r['status']}] {r['title']} ({r['risk']} risk, {r['reversibility']})"
                                            for r in d["remediations"]] or ["- None"])
    lines += ["", "## Activity", ""] + [f"- `{a['created_at']:%Y-%m-%d %H:%M:%S}` {a['actor']}: {a['kind']} {a['body']}" for a in d["activity"]]
    lines += ["", f"_Generated {utcnow():%Y-%m-%d %H:%M:%S} UTC by CampaignShield. Hypotheses are not established facts unless marked verified._"]
    return "\n".join(lines)


class PlanRequest(BaseModel):
    incident_id: str


@router.post("/remediations/plan", status_code=201)
def plan(body: PlanRequest, ctx: Ctx = Depends(require("operator"))):
    inc = owned(ctx.db, Incident, body.incident_id, ctx.org.id)
    return [to_dict(r) for r in remediation.plan(ctx.db, ctx.org, inc)]


class Execute(BaseModel):
    confirm: bool = False


@router.post("/remediations/{remediation_id}/execute")
def execute(remediation_id: str, body: Execute, ctx: Ctx = Depends(require("operator"))):
    if not body.confirm:
        raise HTTPException(422, "Explicit confirmation is required for external state changes")
    rem = owned(ctx.db, Remediation, remediation_id, ctx.org.id)
    return to_dict(remediation.execute(ctx.db, ctx.org, rem, ctx.user, ctx.role))


class Complete(BaseModel):
    status: str = Field("done", pattern="^(done|skipped)$")


@router.post("/remediations/{remediation_id}/complete")
def complete(remediation_id: str, body: Complete, ctx: Ctx = Depends(require("operator"))):
    rem = owned(ctx.db, Remediation, remediation_id, ctx.org.id)
    return to_dict(remediation.complete_manual(ctx.db, ctx.org, rem, ctx.user, body.status))
