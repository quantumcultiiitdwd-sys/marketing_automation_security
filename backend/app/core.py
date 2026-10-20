"""Cross-cutting records: audit chain, internal events, notifications."""

import hashlib
import json
import logging
import threading
import uuid

import httpx
from sqlalchemy import select

from .db import utcnow
from .models import AuditRecord, Event, Notification, Organization
from .security import check_url_safe, redact

log = logging.getLogger("campaignshield")


def audit(db, org_id: str, actor: str, action: str, resource: str, details: dict | None = None) -> AuditRecord:
    """Append-only, hash-chained audit record (tamper-evident per organization)."""
    details = redact(details or {})
    prev = db.scalar(
        select(AuditRecord.hash).where(AuditRecord.organization_id == org_id).order_by(AuditRecord.seq.desc()).limit(1)
    ) or "0" * 64
    ts = utcnow()
    body = json.dumps([prev, actor, action, resource, details, ts.isoformat()], sort_keys=True, default=str)
    rec = AuditRecord(
        organization_id=org_id, actor=actor, action=action, resource=resource, details=details,
        prev_hash=prev, hash=hashlib.sha256(body.encode()).hexdigest(), created_at=ts,
    )
    # ponytail: concurrent writers can fork the chain; serialize with a per-org advisory lock if strict ordering is required.
    db.add(rec)
    db.flush()
    return rec


def verify_audit_chain(db, org_id: str) -> dict:
    prev = "0" * 64
    rows = db.scalars(select(AuditRecord).where(AuditRecord.organization_id == org_id).order_by(AuditRecord.seq)).all()
    for r in rows:
        body = json.dumps([r.prev_hash, r.actor, r.action, r.resource, r.details, r.created_at.isoformat()], sort_keys=True, default=str)
        if r.prev_hash != prev or hashlib.sha256(body.encode()).hexdigest() != r.hash:
            return {"valid": False, "broken_at_seq": r.seq, "records": len(rows)}
        prev = r.hash
    return {"valid": True, "records": len(rows)}


def emit(db, org_id: str, event_type: str, *, trace_id=None, resource_type=None, resource_id=None,
         severity="info", payload=None, integration_id=None, occurred_at=None, source="campaignshield", correlation_id=None) -> Event:
    """Record an internal event so gateway/policy activity shows up on the same timeline as telemetry."""
    ev = Event(
        organization_id=org_id, event_id=f"cs:{uuid.uuid4()}", integration_id=integration_id, source=source,
        event_type=event_type, occurred_at=occurred_at or utcnow(), trace_id=trace_id, correlation_id=correlation_id,
        resource_type=resource_type, resource_id=resource_id, severity=severity, payload=redact(payload or {}),
    )
    db.add(ev)
    db.flush()
    return ev


def notify(db, org: Organization, title: str, body: str = "", severity: str = "info", link: str | None = None):
    db.add(Notification(organization_id=org.id, title=title, body=body, severity=severity, link=link))
    url = (org.settings or {}).get("notify_webhook_url")
    if url:
        threading.Thread(target=_post_webhook, args=(url, {"text": f"[{severity.upper()}] {title}\n{body}"}), daemon=True).start()


def _post_webhook(url: str, payload: dict):
    try:
        check_url_safe(url)
        httpx.post(url, json=payload, timeout=5)
    except Exception as e:  # notification failures must never break the request path
        log.warning("notification delivery failed: %s", e)
