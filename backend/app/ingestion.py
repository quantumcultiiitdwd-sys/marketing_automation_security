import json
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .db import utcnow
from .detection import on_event
from .models import Event, Integration, Organization, QuarantinedEvent, Workflow
from .security import redact

MAX_EVENT_BYTES = 32_000


class ResourceRef(BaseModel):
    type: str = Field(max_length=50)
    id: str = Field(max_length=200)


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=1, max_length=128)
    source: str = Field(max_length=50)
    event_type: str = Field(pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)+$", max_length=100)
    occurred_at: datetime
    trace_id: str | None = Field(None, max_length=128)
    correlation_id: str | None = Field(None, max_length=128)
    resource: ResourceRef | None = None
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    payload: dict = Field(default_factory=dict)
    schema_version: Literal["1.0"] = "1.0"
    # Accepted for compatibility but always overwritten from the authenticated integration.
    organization_id: str | None = None
    integration_id: str | None = None
    received_at: datetime | None = None


_ERROR_PATTERNS = [
    ("api_timeout", r"time(d)?\s?out|ETIMEDOUT|ECONNABORTED"),
    ("auth_error", r"\b401\b|\b403\b|unauthori[sz]ed|forbidden|credential|token (has )?expired|invalid_grant"),
    ("rate_limited", r"\b429\b|rate.?limit|quota|RESOURCE_EXHAUSTED"),
    ("upstream_5xx", r"\b50[0-9]\b|bad gateway|service unavailable|ECONNRESET|ECONNREFUSED"),
    ("invalid_config", r"\b400\b|\b422\b|invalid|validation|missing (required )?param|not found"),
]


def classify_error(message: str | None) -> str | None:
    if not message:
        return None
    for name, pat in _ERROR_PATTERNS:
        if re.search(pat, message, re.I):
            return name
    return "unknown_error"


def _ts(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if isinstance(v, str) else v


def normalize_n8n(ex: dict, integration_id: str) -> dict:
    """Map an n8n execution object (public API or instrumentation workflow) to the canonical schema."""
    status = ex.get("status") or ("success" if ex.get("finished") else "error")
    event_type = {
        "success": "workflow.execution.succeeded", "error": "workflow.execution.failed",
        "crashed": "workflow.execution.failed", "canceled": "workflow.execution.canceled",
        "running": "workflow.execution.started", "waiting": "workflow.execution.started",
    }.get(status, "workflow.execution.unknown")
    err = ex.get("error") or (ex.get("data") or {}).get("resultData", {}).get("error") or {}
    if not isinstance(err, dict):
        err = {"message": str(err)}
    message = err.get("message")
    started, stopped = _ts(ex.get("startedAt")), _ts(ex.get("stoppedAt"))
    root = ex.get("retryOf") or ex.get("id")
    payload = {
        "execution_id": str(ex.get("id")), "workflow_name": ex.get("workflowName") or (ex.get("workflowData") or {}).get("name"),
        "status": status, "mode": ex.get("mode"), "retry_of": ex.get("retryOf"),
        "retry_count": ex.get("retryCount", 1 if ex.get("retryOf") else 0),
        "error_message": (message or "")[:500] or None, "error_type": ex.get("errorType") or classify_error(message),
        "failed_node": (err.get("node") or {}).get("name") if isinstance(err.get("node"), dict) else err.get("node"),
        "duration_ms": int((stopped - started).total_seconds() * 1000) if started and stopped else None,
    }
    return {
        "event_id": f"n8n:{integration_id}:{ex.get('id')}:{status}",
        "source": "n8n",
        "event_type": event_type,
        "occurred_at": (stopped or started or utcnow()).isoformat(),
        "trace_id": ex.get("traceId") or f"n8n-exec-{root}",
        "correlation_id": ex.get("correlationId"),
        "resource": {"type": "workflow", "id": str(ex.get("workflowId"))},
        "severity": "medium" if event_type.endswith("failed") else "info",
        "payload": {k: v for k, v in payload.items() if v is not None},
    }


def ingest(db, org: Organization, integ: Integration, items: list) -> dict:
    out = {"accepted": 0, "duplicates": 0, "quarantined": 0, "errors": []}
    for i, raw in enumerate(items):
        try:
            if not isinstance(raw, dict):
                raise ValueError("Event must be an object")
            if "n8n" in raw and isinstance(raw["n8n"], dict):
                raw = {**normalize_n8n(raw["n8n"], integ.id), **{k: v for k, v in raw.items() if k in ("trace_id", "correlation_id") and v}}
            if len(json.dumps(raw, default=str)) > MAX_EVENT_BYTES:
                raise ValueError(f"Event exceeds {MAX_EVENT_BYTES} bytes")
            ev = CanonicalEvent.model_validate(raw)
            occurred = ev.occurred_at if ev.occurred_at.tzinfo else ev.occurred_at.replace(tzinfo=timezone.utc)
            if occurred > utcnow() + timedelta(hours=1):
                raise ValueError("occurred_at is in the future")
        except (ValidationError, ValueError, TypeError) as e:
            msg = e.errors(include_url=False)[0]["msg"] if isinstance(e, ValidationError) else str(e)
            db.add(QuarantinedEvent(organization_id=org.id, integration_id=integ.id,
                                    raw=redact(raw) if isinstance(raw, dict) else {"value": str(raw)[:1000]}, error=msg))
            out["quarantined"] += 1
            out["errors"].append({"index": i, "error": msg})
            continue

        if db.scalar(select(Event.id).where(Event.organization_id == org.id, Event.event_id == ev.event_id)):
            out["duplicates"] += 1
            continue
        row = Event(
            organization_id=org.id, event_id=ev.event_id, integration_id=integ.id, source=ev.source,
            event_type=ev.event_type, occurred_at=occurred, trace_id=ev.trace_id, correlation_id=ev.correlation_id,
            resource_type=ev.resource.type if ev.resource else None, resource_id=ev.resource.id if ev.resource else None,
            severity=ev.severity, payload=redact(ev.payload), schema_version=ev.schema_version,
        )
        try:
            with db.begin_nested():
                db.add(row)
        except IntegrityError:  # concurrent delivery of the same event
            out["duplicates"] += 1
            continue
        process(db, org, integ, row)
        out["accepted"] += 1
    db.commit()
    return out


def process(db, org: Organization, integ: Integration, ev: Event):
    wf = None
    if ev.resource_type == "workflow" and ev.resource_id:
        wf = db.scalar(select(Workflow).where(Workflow.integration_id == integ.id, Workflow.external_id == ev.resource_id))
        if not wf:  # discovery from telemetry
            wf = Workflow(organization_id=org.id, integration_id=integ.id, external_id=ev.resource_id,
                          name=ev.payload.get("workflow_name") or ev.resource_id)
            db.add(wf)
            db.flush()
        is_execution = ev.event_type.startswith("workflow.execution.") and not ev.event_type.endswith("started")
        # Out-of-order safe: only newer executions move the "last seen" state.
        if is_execution and (not wf.last_execution_at or ev.occurred_at >= wf.last_execution_at):
            wf.last_execution_at = ev.occurred_at
            wf.last_status = ev.event_type.rsplit(".", 1)[-1]
    on_event(db, org, ev, wf)
