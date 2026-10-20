"""Evidence-grounded root-cause investigation.

Timeline entries are observed facts. Hypotheses are inferences: ranked by a heuristic
(pattern prior × temporal consistency + evidence volume), never marked verified until a human confirms.
"""

from datetime import timedelta

from sqlalchemy import or_, select

from .db import utcnow
from .models import Event, Incident, IncidentEvidence, Workflow

SCHEMA_VERSION = "1.0"
_FAIL = ("workflow.execution.failed", "action.failed", "integration.check.failed")


def _describe(e: Event) -> str:
    p = e.payload or {}
    t = e.event_type
    if t == "workflow.execution.failed":
        return f"Execution {p.get('execution_id', '')} failed: {p.get('error_type', 'error')}" + (f" — {p['error_message']}" if p.get("error_message") else "")
    if t == "workflow.execution.succeeded":
        return f"Execution {p.get('execution_id', '')} succeeded"
    if t == "action.requested":
        return f"Agent '{p.get('agent')}' requested {p.get('action_type')}"
    if t == "policy.decision":
        failed = [r["message"] for r in p.get("reasons", []) if r.get("outcome") != "ALLOW"] or ["all policies passed"]
        return f"Policy decision: {p.get('decision')} — " + "; ".join(failed[:3])
    if t == "action.executed":
        return f"{p.get('action_type')} executed by {p.get('actor')} (verified={p.get('verified')})"
    if t == "action.failed":
        return f"{p.get('action_type')} failed: {p.get('error_type')}"
    if t == "action.duplicate_suppressed":
        return f"Replay of idempotency key '{p.get('idempotency_key')}' suppressed (original: {p.get('original_status')})"
    if t == "provider.outreach.sent":
        return f"Provider delivered outreach to {p.get('recipient_count')} recipients"
    if t == "workflow.config.changed":
        return f"Workflow configuration changed to version {p.get('to_version')}"
    if t == "campaign.budget.changed":
        return f"Budget changed {p.get('from')} → {p.get('to')}"
    if t.startswith("approval."):
        return f"Approval {t.split('.')[1]} by {p.get('by')}"
    if t == "integration.check.failed":
        return f"Integration health check failed: {p.get('error_type')}"
    return t


def _hyp(cause, prior, evidence, explanation, anchor, missing=None, next_steps=None):
    return {"cause": cause, "prior": prior, "evidence": evidence, "explanation": explanation, "anchor": anchor,
            "missing_evidence": missing or [], "next_steps": next_steps or []}


def _hypotheses(inc: Incident, events: list[Event], symptom_at) -> list[dict]:
    by_err: dict[str, list[Event]] = {}
    for e in events:
        if e.event_type in _FAIL and e.payload.get("error_type"):
            by_err.setdefault(e.payload["error_type"], []).append(e)
    of = lambda *types: [e for e in events if e.event_type in types]  # noqa: E731
    out = []

    for err, cause, prior, steps in [
        ("api_timeout", "Upstream API timeout in a dependency", 0.75, ["Check the dependency's status page and latency", "Add timeout + backoff to the failing node"]),
        ("upstream_5xx", "Upstream service outage (5xx / connection errors)", 0.75, ["Confirm provider status", "Pause dependent workflows until recovery"]),
        ("auth_error", "Expired or revoked credential", 0.85, ["Re-authorize the credential used by the failing node", "Rotate the key if compromise is suspected"]),
        ("rate_limited", "Provider rate limiting or quota exhaustion", 0.7, ["Reduce polling frequency or batch requests", "Request a quota increase"]),
        ("invalid_config", "Invalid workflow or request configuration", 0.7, ["Inspect the failing node's parameters", "Roll back to the last known-good version"]),
    ]:
        hits = by_err.get(err, [])
        if hits:
            out.append(_hyp(cause, prior, hits, f"{len(hits)} failure event(s) classified as {err}, first at {hits[0].occurred_at:%H:%M:%S}",
                            hits[0].occurred_at, next_steps=steps))

    changes = [e for e in of("workflow.config.changed", "campaign.budget.changed", "campaign.status.changed") if e.occurred_at <= symptom_at + timedelta(minutes=5)]
    if changes:
        last = changes[-1]
        cfg_errs = by_err.get("invalid_config", [])
        if cfg_errs and last.occurred_at <= cfg_errs[0].occurred_at:
            out.append(_hyp("Configuration change introduced an invalid configuration", 0.9, [last] + cfg_errs[:3],
                            f"Config changed at {last.occurred_at:%H:%M:%S}; invalid-config failures began at {cfg_errs[0].occurred_at:%H:%M:%S}",
                            last.occurred_at, next_steps=["Roll back to the previous workflow version", "Diff the two versions"]))
        else:
            out.append(_hyp("Recent configuration change", 0.5, changes[-3:], f"{len(changes)} change(s) before the symptom; last at {last.occurred_at:%H:%M:%S}",
                            last.occurred_at, missing=["Change author and diff are not available from the provider"]))

    dups = of("action.duplicate_suppressed")
    if dups:
        timeouts = [e for e in of("action.failed") if e.payload.get("error_type") == "api_timeout"]
        if timeouts:
            out.append(_hyp("Client retried after a downstream timeout (original had already been delivered)", 0.9, timeouts + dups + of("provider.outreach.sent"),
                            f"Timeout at {timeouts[0].occurred_at:%H:%M:%S} followed by {len(dups)} replay(s) of the same idempotency key",
                            timeouts[0].occurred_at, next_steps=["Inspect original downstream delivery state", "Disable unsafe retry-on-fail for this node",
                                                                 "Keep sending a stable idempotency key on retries"]))
        else:
            out.append(_hyp("Client retried an already-completed action", 0.6, dups, f"{len(dups)} replay(s) without a recorded failure",
                            dups[0].occurred_at, missing=["Client-side retry logs"], next_steps=["Review the caller's retry policy"]))

    denials = [e for e in of("policy.decision") if e.payload.get("decision") in ("DENY", "REQUIRE_APPROVAL")]
    if denials:
        rules = sorted({r["rule"] for e in denials for r in e.payload.get("reasons", []) if r["outcome"] != "ALLOW"})
        out.append(_hyp(f"Agent requested an action outside policy limits ({', '.join(rules)})", 0.9, of("action.requested") + denials,
                        "The gateway evaluated the request against active policies and recorded the violation",
                        denials[0].occurred_at, next_steps=["Review the agent's objective and inputs", "Tighten the agent's allowed actions"]))
        out.append(_hyp("Agent misconfiguration or manipulated input (e.g. prompt injection)", 0.25, of("action.requested"),
                        "Possible, but agent reasoning is not observable to CampaignShield", denials[0].occurred_at,
                        missing=["Agent prompt and tool-call logs are not ingested"], next_steps=["Inspect the agent's recent inputs for untrusted content"]))

    if inc.kind == "spend_anomaly":
        raises = [e for e in of("action.executed") if e.payload.get("action_type") == "ads.campaign.update_budget"] + \
                 [e for e in of("campaign.budget.changed") if (e.payload.get("to") or 0) > (e.payload.get("from") or 0)]
        if raises:
            out.append(_hyp("Budget increase enabled the spend spike", 0.8, raises, f"Budget raised at {raises[-1].occurred_at:%H:%M:%S} before the anomaly",
                            raises[-1].occurred_at, next_steps=["Restore the previous budget", "Require approval for budget increases"]))
        out.append(_hyp("Auction or bid-strategy change on the provider side", 0.3, [], "Consistent with a spike but not directly observable",
                        symptom_at, missing=["Auction insights and bid-strategy history are not collected"],
                        next_steps=["Compare CPC and impression share against the prior week"]))

    if inc.kind == "missing_heartbeat":
        out.append(_hyp("Trigger stopped firing (schedule disabled or upstream webhook stopped)", 0.45, [],
                        "No executions arrived within the expected interval", symptom_at,
                        missing=["Trigger configuration and webhook delivery logs"], next_steps=["Open the workflow trigger and confirm it is enabled"]))
    if inc.kind == "metrics_delayed":
        out.append(_hyp("Provider reporting delay", 0.6, [], "Advertising metrics commonly lag by several hours", symptom_at,
                        next_steps=["Wait for the next sync before acting on spend data"]))
    return out


def investigate(db, inc: Incident) -> dict:
    ev_rows = db.scalars(select(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id)).all()
    linked_ids = [e.event_id for e in ev_rows if e.event_id]
    resource_ids = {r for r in (inc.resource_id, inc.integration_id) if r}
    if inc.resource_type == "workflow" and inc.resource_id:
        wf = db.get(Workflow, inc.resource_id)
        if wf:
            resource_ids.add(wf.external_id)
    traces = set(db.scalars(select(Event.trace_id).where(Event.id.in_(linked_ids), Event.trace_id.is_not(None))).all()) if linked_ids else set()

    start, end = inc.detected_at - timedelta(hours=6), max(inc.last_seen_at, inc.detected_at) + timedelta(hours=1)
    conds = [Event.id.in_(linked_ids)] if linked_ids else []
    if resource_ids:
        conds.append(Event.resource_id.in_(resource_ids))
    if traces:
        conds.append(Event.trace_id.in_(traces))
    if inc.integration_id:
        conds.append((Event.integration_id == inc.integration_id) & Event.event_type.in_(["integration.check.failed", "integration.recovered"]))
    events = db.scalars(select(Event).where(Event.organization_id == inc.organization_id, Event.occurred_at.between(start, end),
                                            or_(*conds)).order_by(Event.occurred_at).limit(300)).all() if conds else []
    # Pull in every event sharing a trace with what we found (gateway → provider → retries).
    more = {e.trace_id for e in events if e.trace_id} - traces
    if more:
        extra = db.scalars(select(Event).where(Event.organization_id == inc.organization_id, Event.trace_id.in_(more))).all()
        events = sorted({e.id: e for e in [*events, *extra]}.values(), key=lambda e: e.occurred_at)[:300]

    symptom_at = next((e.occurred_at for e in events if e.id in linked_ids), inc.detected_at)
    hyps = _hypotheses(inc, events, symptom_at)
    for h in hyps:
        delta = (symptom_at - h["anchor"]).total_seconds()
        temporal = 1.0 if 0 <= delta <= 3600 else 0.8 if delta > 3600 else 0.6  # causes should precede symptoms
        h["score"] = round(h["prior"] * temporal + 0.04 * min(len(h["evidence"]), 5), 3)
    hyps.sort(key=lambda h: h["score"], reverse=True)

    previous = {(h["cause"]): h for h in (inc.rca or {}).get("hypotheses", [])}
    hypotheses = []
    for i, h in enumerate(hyps[:5], 1):
        prev = previous.get(h["cause"], {})
        hypotheses.append({
            "rank": i, "cause": h["cause"], "explanation": h["explanation"], "score": h["score"],
            "confidence_label": "high" if h["score"] >= 0.8 else "medium" if h["score"] >= 0.5 else "low",
            "confidence_method": "heuristic (pattern prior × temporal consistency + evidence count); not calibrated",
            "evidence_ids": [e.id for e in h["evidence"]][:10], "missing_evidence": h["missing_evidence"],
            "next_steps": h["next_steps"], "verified": prev.get("verified", False), "feedback": prev.get("feedback"),
        })
    if not hypotheses:
        hypotheses.append({"rank": 1, "cause": "Insufficient evidence to determine a cause", "explanation": "No known failure pattern matched the observed events",
                           "score": 0, "confidence_label": "low", "confidence_method": "n/a", "evidence_ids": [],
                           "missing_evidence": ["Execution payloads or provider logs for the affected resource"],
                           "next_steps": ["Confirm or describe the cause so future investigations improve"], "verified": False, "feedback": None})

    blast = {
        "resources": sorted({f"{e.resource_type}:{e.resource_id}" for e in events if e.resource_type and e.resource_type != "action"}),
        "traces": len({e.trace_id for e in events if e.trace_id}),
        "failed_executions": sum(e.event_type == "workflow.execution.failed" for e in events),
        "actions_executed": sum(e.event_type == "action.executed" for e in events),
        "actions_blocked": sum(e.event_type == "policy.decision" and e.payload.get("decision") == "DENY" for e in events),
        "duplicates_suppressed": sum(e.event_type == "action.duplicate_suppressed" for e in events),
        "messages_delivered": sum(int(e.payload.get("recipient_count") or 0) for e in events if e.event_type == "provider.outreach.sent"),
    }
    top = hypotheses[0]
    span = f" between {events[0].occurred_at:%Y-%m-%d %H:%M} and {events[-1].occurred_at:%H:%M} UTC" if events else ""
    summary = (f"Observed {len(events)} related event(s) across {blast['traces']} trace(s){span}. "
               f"Leading hypothesis ({top['confidence_label']} confidence, {'verified' if top['verified'] else 'unverified'}): {top['cause']}. "
               + (f"Missing evidence: {'; '.join(top['missing_evidence'])}." if top["missing_evidence"] else ""))
    inc.rca = {
        "schema_version": SCHEMA_VERSION, "generated_at": utcnow().isoformat(), "status": "complete" if events else "insufficient_data",
        "summary": summary, "symptom_at": symptom_at.isoformat(),
        "timeline": [{"event_id": e.id, "at": e.occurred_at.isoformat(), "type": e.event_type, "source": e.source, "severity": e.severity,
                      "trace_id": e.trace_id, "description": _describe(e), "fact": True, "is_symptom": e.id in linked_ids} for e in events],
        "hypotheses": hypotheses, "blast_radius": blast, "feedback": (inc.rca or {}).get("feedback", []),
    }
    db.flush()
    return inc.rca
