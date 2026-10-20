from fastapi import HTTPException
from sqlalchemy import select

from .core import audit, notify
from .db import utcnow
from .models import Alert, Incident, IncidentActivity, IncidentEvidence, Organization

SEVERITIES = ["low", "medium", "high", "critical"]
STATUSES = ["open", "investigating", "awaiting_approval", "mitigating", "resolved", "closed"]
TRANSITIONS = {
    "open": {"investigating", "awaiting_approval", "mitigating", "resolved", "closed"},
    "investigating": {"open", "awaiting_approval", "mitigating", "resolved", "closed"},
    "awaiting_approval": {"investigating", "mitigating", "resolved", "closed"},
    "mitigating": {"investigating", "resolved"},
    "resolved": {"closed", "open"},
    "closed": {"open"},
}
ACTIVE = ("open", "investigating", "awaiting_approval", "mitigating")


def _suppressed(org: Organization, dedup_key: str) -> bool:
    now = utcnow().isoformat()
    return any(dedup_key.startswith(s["prefix"]) and s["until"] > now for s in (org.settings or {}).get("suppressions", []))


def raise_incident(
    db, org: Organization, *, kind: str, title: str, severity: str, dedup_key: str, detector: str,
    message: str = "", resource_type=None, resource_id=None, integration_id=None, confidence="medium",
    evidence: dict | None = None, event_ids: list[str] | None = None, status: str = "open",
) -> Incident | None:
    """Record an alert and attach it to an open incident with the same dedup key, or open a new one."""
    alert = Alert(
        organization_id=org.id, detector=detector, resource_type=resource_type, resource_id=resource_id,
        severity=severity, confidence=confidence, message=message or title, evidence=evidence or {},
    )
    db.add(alert)
    if _suppressed(org, dedup_key):
        alert.evidence = {**alert.evidence, "suppressed": True}
        db.flush()
        return None

    inc = db.scalars(
        select(Incident).where(Incident.organization_id == org.id, Incident.dedup_key == dedup_key, Incident.status.in_(ACTIVE))
    ).first()
    if inc:
        inc.occurrence_count += 1
        inc.last_seen_at = utcnow()
        if SEVERITIES.index(severity) > SEVERITIES.index(inc.severity):
            inc.severity = severity
            _activity(db, inc, "system", "system", {"message": f"Severity escalated to {severity}"})
    else:
        inc = Incident(
            organization_id=org.id, title=title, kind=kind, severity=severity, status=status, dedup_key=dedup_key,
            resource_type=resource_type, resource_id=resource_id, integration_id=integration_id,
        )
        db.add(inc)
        db.flush()
        _activity(db, inc, "system", "status", {"to": status, "message": "Incident created by " + detector})
        audit(db, org.id, f"detector:{detector}", "incident.created", f"incident:{inc.id}", {"title": title, "severity": severity})
        notify(db, org, f"{severity.title()} incident: {title}", message, severity, f"/incidents/{inc.id}")
    db.flush()
    alert.incident_id = inc.id
    db.add(IncidentEvidence(incident_id=inc.id, evidence_type=detector, data={"message": message or title, "confidence": confidence, **(evidence or {})}))
    for eid in event_ids or []:
        db.add(IncidentEvidence(incident_id=inc.id, event_id=eid, evidence_type="event"))
    db.flush()

    from .rca import investigate  # deferred: rca imports incident helpers

    investigate(db, inc)
    return inc


def _activity(db, inc: Incident, actor: str, kind: str, body: dict):
    db.add(IncidentActivity(incident_id=inc.id, actor=actor, kind=kind, body=body))


def transition(db, inc: Incident, to: str, actor: str, note: str | None = None):
    if to == inc.status:
        return
    if to not in TRANSITIONS.get(inc.status, set()):
        raise HTTPException(409, f"Cannot move incident from {inc.status} to {to}")
    frm, inc.status = inc.status, to
    now = utcnow()
    if to in ("investigating", "mitigating", "awaiting_approval") and not inc.acknowledged_at:
        inc.acknowledged_at = now
    if to == "resolved":
        inc.resolved_at = now
        inc.resolution = note or inc.resolution
    if to == "open":
        inc.resolved_at = None
    _activity(db, inc, actor, "status", {"from": frm, "to": to, "note": note})
    audit(db, inc.organization_id, actor, "incident.status_changed", f"incident:{inc.id}", {"from": frm, "to": to, "note": note})
