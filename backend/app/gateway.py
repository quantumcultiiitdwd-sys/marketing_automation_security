"""Controlled action gateway: authenticate → normalize → idempotency → policy → (approve) → execute → verify → audit."""

import hashlib
import json
import uuid
from datetime import timedelta

from fastapi import HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from . import connectors, policy
from .connectors import ACTIONS, ProviderError
from .core import audit, emit, notify
from .db import utcnow
from .deps import role_at_least
from .incidents import raise_incident, transition
from .models import ActionRequest, Agent, Event, Approval, Campaign, Incident, Integration, Organization, Policy, PolicyDecision, Workflow
from .security import redact


class ActionEnvelope(BaseModel):
    action_type: str = Field(max_length=100)
    target: dict = Field(default_factory=dict)
    parameters: dict = Field(default_factory=dict)
    idempotency_key: str | None = Field(None, min_length=1, max_length=200)
    trace_id: str | None = Field(None, max_length=128)
    reason: str | None = Field(None, max_length=2000)  # agent-supplied, untrusted


def fingerprint(org_id: str, action_type: str, target: dict, params: dict) -> str:
    body = json.dumps([org_id, action_type, target, {k: v for k, v in params.items() if k != "simulate_timeout"}], sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def resolve_target(db, org_id: str, action_type: str, target: dict):
    """Returns (integration, resource). Raises 422 when the target does not belong to this tenant."""
    meta = ACTIONS.get(action_type)
    if not meta:
        return None, None
    kind = meta["resource"]
    if kind == "agent":
        agent = db.get(Agent, target.get("agent_id", ""))
        if not agent or agent.organization_id != org_id:
            raise HTTPException(422, "Target agent not found")
        return None, agent
    if kind is None:  # outreach: the org's outreach integration
        integ = db.scalar(select(Integration).where(Integration.organization_id == org_id, Integration.provider == meta["provider"],
                                                    Integration.status != "revoked"))
        if not integ:
            raise HTTPException(422, f"No {meta['provider']} integration connected")
        return integ, None
    model, key = (Campaign, "campaign_id") if kind == "campaign" else (Workflow, "workflow_id")
    ref = str(target.get(key, ""))
    q = select(model).where(model.organization_id == org_id, (model.id == ref) | (model.external_id == ref))
    if target.get("integration_id"):
        q = q.where(model.integration_id == target["integration_id"])
    res = db.scalars(q).first()
    if not res:
        raise HTTPException(422, f"Target {kind} not found")
    integ = db.get(Integration, res.integration_id)
    if integ.status == "revoked":
        raise HTTPException(422, "Integration has been revoked")
    return integ, res


def _active_policies(db, org_id: str) -> list:
    return db.scalars(select(Policy).where(Policy.organization_id == org_id, Policy.active.is_(True))).all()


def build_context(db, org: Organization, env: ActionEnvelope, state: dict, agent: Agent | None, user_role: str | None):
    def count_recent(seconds: int) -> int:
        return db.scalar(select(func.count()).select_from(ActionRequest).where(
            ActionRequest.agent_id == agent.id, ActionRequest.created_at >= utcnow() - timedelta(seconds=seconds)))

    return policy.ActionContext(
        action_type=env.action_type, parameters=env.parameters, state=state, has_idempotency_key=bool(env.idempotency_key),
        agent_id=agent.id if agent else None, agent_allowed=agent.allowed_actions if agent else [],
        agent_status=agent.status if agent else "active", user_role=user_role,
        kill_switch=bool((org.settings or {}).get("kill_switch")), count_recent=count_recent,
    )


def evaluate_safely(db, org, env, agent=None, user_role=None, policies=None):
    """Policy evaluation that fails closed: any error resolving state or evaluating rules is a DENY.
    Returns (decision, integration, resource, state_snapshot)."""
    integ = res = None
    state: dict = {}
    try:
        if env.action_type == "ads.campaign.update_budget":
            float(env.parameters["proposed_daily_budget"])
        integ, res = resolve_target(db, org.id, env.action_type, env.target)
        state = connectors.read_state(db, integ, env.action_type, res) if env.action_type in ACTIONS else {}
        if res is not None and env.action_type.startswith("ads.") and env.parameters.get("currency") not in (None, res.currency):
            reason = policy._reason("currency_mismatch", f"Campaign currency is {res.currency}", policy.DENY)
            return policy.Decision(policy.DENY, [reason], []), integ, res, state
        ctx = build_context(db, org, env, state, agent, user_role)
        decision = policy.evaluate(policies if policies is not None else _active_policies(db, org.id), ctx)
    except HTTPException as e:
        decision = policy.Decision(policy.DENY, [policy._reason("invalid_target", str(e.detail), policy.DENY)], [])
    except Exception as e:  # FR-GRD-014: fail closed
        msg = f"Policy evaluation failed ({type(e).__name__}); failing closed"
        decision = policy.Decision(policy.DENY, [policy._reason("policy_error", msg, policy.DENY)], [])
    return decision, integ, res, state


def submit(db, org: Organization, env: ActionEnvelope, agent: Agent) -> dict:
    trace_id = env.trace_id or f"trace-{uuid.uuid4().hex[:16]}"
    fp = fingerprint(org.id, env.action_type, env.target, env.parameters)
    if env.idempotency_key:
        dup = _handle_duplicate(db, org, env, fp, agent)
        if dup:
            return dup

    act = ActionRequest(organization_id=org.id, agent_id=agent.id, action_type=env.action_type, target=env.target,
                        parameters=redact(env.parameters), idempotency_key=env.idempotency_key, fingerprint=fp, trace_id=trace_id)
    try:
        with db.begin_nested():
            db.add(act)
    except IntegrityError:  # lost a race with an identical concurrent request
        return _handle_duplicate(db, org, env, fp, agent)
    emit(db, org.id, "action.requested", trace_id=trace_id, resource_type="action", resource_id=act.id, correlation_id=act.id,
         payload={"action_type": env.action_type, "agent": agent.name, "target": env.target, "parameters": env.parameters,
                  "agent_reason": env.reason, "idempotency_key": env.idempotency_key})

    decision, integ, res, state = evaluate_safely(db, org, env, agent=agent)
    act.prior_state = state  # snapshot at decision time; used to detect stale approvals
    _record_decision(db, org, act, decision, trace_id)
    resource_id = getattr(res, "id", None)

    if decision.decision == policy.DENY:
        act.status = "denied"
        raise_incident(db, org, kind="policy_violation", title=f"Blocked {env.action_type} by agent '{agent.name}'", severity="high",
                       dedup_key=f"deny:{agent.id}:{env.action_type}:{resource_id}", detector="guardrail",
                       resource_type=ACTIONS.get(env.action_type, {}).get("resource") or "action", resource_id=resource_id,
                       integration_id=getattr(integ, "id", None), confidence="high",
                       message="; ".join(r["message"] for r in decision.reasons if r["outcome"] == policy.DENY),
                       evidence={"action_id": act.id, "decision": decision.as_dict()}, event_ids=_trace_event_ids(db, org.id, trace_id))
    elif decision.decision == policy.REQUIRE_APPROVAL:
        act.status = "pending_approval"
        inc = raise_incident(db, org, kind="policy_violation", title=f"Approval required: {env.action_type} by '{agent.name}'",
                             severity="medium", dedup_key=f"approval:{act.id}", detector="guardrail", status="awaiting_approval",
                             resource_type=ACTIONS[env.action_type]["resource"] or "action", resource_id=resource_id,
                             integration_id=getattr(integ, "id", None), confidence="high",
                             message="; ".join(r["message"] for r in decision.reasons if r["outcome"] == policy.REQUIRE_APPROVAL),
                             evidence={"action_id": act.id, "decision": decision.as_dict()}, event_ids=_trace_event_ids(db, org.id, trace_id))
        db.add(Approval(organization_id=org.id, action_id=act.id, incident_id=inc.id if inc else None, requested_by=f"agent:{agent.name}",
                        required_role=decision.approval_role, reasons=decision.reasons))
        notify(db, org, f"Approval needed: {env.action_type}", f"Requested by agent {agent.name}", "medium", "/approvals")
    else:
        params = decision.modified_parameters or env.parameters
        db.commit()  # persist decision before touching the provider
        _execute(db, org, act, integ, res, params, actor=f"agent:{agent.name}")
    audit(db, org.id, f"agent:{agent.name}", "action.decision", f"action:{act.id}",
          {"action_type": env.action_type, "decision": decision.decision, "policy_refs": decision.policy_refs})
    db.commit()
    return serialize(act, policy=decision.as_dict())


def _trace_event_ids(db, org_id, trace_id):
    return db.scalars(select(Event.id).where(Event.organization_id == org_id, Event.trace_id == trace_id)).all()


def _record_decision(db, org, act, decision, trace_id):
    act.decision = decision.decision
    db.add(PolicyDecision(organization_id=org.id, action_id=act.id, action_type=act.action_type, decision=decision.decision,
                          reasons=decision.reasons, policy_refs=decision.policy_refs, trace_id=trace_id))
    emit(db, org.id, "policy.decision", trace_id=trace_id, resource_type="action", resource_id=act.id, correlation_id=act.id,
         severity="high" if decision.decision == policy.DENY else "medium" if decision.decision == policy.REQUIRE_APPROVAL else "info",
         payload=decision.as_dict())


def _handle_duplicate(db, org, env, fp, agent) -> dict | None:
    existing = db.scalar(select(ActionRequest).where(ActionRequest.organization_id == org.id, ActionRequest.idempotency_key == env.idempotency_key))
    if not existing:
        return None
    if existing.fingerprint != fp:
        raise HTTPException(409, "Idempotency key was already used for a different action")
    if existing.status == "unknown":  # original outcome was lost (e.g. timeout): reconcile, never blindly re-run
        integ, res = resolve_target(db, org.id, existing.action_type, existing.target)
        state = connectors.read_state(db, integ, existing.action_type, res, existing.id)
        if state.get("delivered") or existing.action_type != "outreach.email.send":
            existing.status, existing.result = "executed", {**(existing.result or {}), "reconciled": True, "observed_state": state}
        else:
            existing.status, existing.result = "failed", {"reconciled": True, "note": "Not delivered; retry with a new idempotency key"}
    ev = emit(db, org.id, "action.duplicate_suppressed", trace_id=existing.trace_id, resource_type="action", resource_id=existing.id,
              correlation_id=existing.id, severity="medium",
              payload={"idempotency_key": env.idempotency_key, "original_status": existing.status, "agent": agent.name,
                       "action_type": env.action_type, "retry_trace_id": env.trace_id})
    raise_incident(db, org, kind="duplicate_action", title=f"Duplicate {env.action_type} suppressed", severity="medium",
                   dedup_key=f"dup:{existing.id}", detector="idempotency", resource_type="action", resource_id=existing.id,
                   confidence="high", message=f"Idempotency key '{env.idempotency_key}' was replayed; only the original was executed",
                   evidence={"original_action_id": existing.id, "original_status": existing.status},
                   event_ids=_trace_event_ids(db, org.id, existing.trace_id) + [ev.id])
    audit(db, org.id, f"agent:{agent.name}", "action.duplicate_suppressed", f"action:{existing.id}", {"idempotency_key": env.idempotency_key})
    db.commit()
    return serialize(existing, duplicate=True)


def _execute(db, org, act: ActionRequest, integ, res, params: dict, actor: str) -> bool:
    act.status = "executing"
    db.commit()
    try:
        prior, result = connectors.execute(db, integ, act.action_type, res, params, act.id, act.trace_id)
        after = connectors.read_state(db, integ, act.action_type, res, act.id)
        verified = all(after.get(k) == v for k, v in result.items() if k in after)
        act.prior_state, act.result, act.status, act.executed_at = prior, {**result, "verified": verified}, "executed", utcnow()
        emit(db, org.id, "action.executed", trace_id=act.trace_id, resource_type=ACTIONS[act.action_type]["resource"] or "action",
             resource_id=getattr(res, "id", act.id), correlation_id=act.id, integration_id=getattr(integ, "id", None),
             payload={"action_type": act.action_type, "prior_state": prior, "result": result, "verified": verified, "actor": actor})
        audit(db, org.id, actor, "action.executed", f"action:{act.id}", {"action_type": act.action_type, "prior": prior, "result": result})
        _fingerprint_check(db, org, act)
        db.commit()
        return True
    except ProviderError as e:
        act.status = "unknown" if e.kind == "timeout" else "failed"
        act.result = {"error": e.kind, "detail": e.detail}
        emit(db, org.id, "action.failed", trace_id=act.trace_id, resource_type="action", resource_id=act.id, correlation_id=act.id,
             integration_id=getattr(integ, "id", None), severity="high",
             payload={"action_type": act.action_type, "error_type": "api_timeout" if e.kind == "timeout" else e.kind, "detail": e.detail})
        audit(db, org.id, actor, "action.failed", f"action:{act.id}", {"error": e.kind, "detail": e.detail})
        db.commit()
        return False


def _fingerprint_check(db, org, act):
    """Same business operation under a different idempotency key: warn, never auto-suppress."""
    similar = db.scalar(select(func.count()).select_from(ActionRequest).where(
        ActionRequest.organization_id == org.id, ActionRequest.fingerprint == act.fingerprint, ActionRequest.id != act.id,
        ActionRequest.status == "executed", ActionRequest.executed_at >= utcnow() - timedelta(minutes=10)))
    if similar and act.action_type == "outreach.email.send":
        raise_incident(db, org, kind="duplicate_action", title="Possible duplicate outreach (different idempotency keys)", severity="low",
                       dedup_key=f"fp:{act.fingerprint}", detector="action_fingerprint", resource_type="action", resource_id=act.id,
                       confidence="low", message=f"{similar + 1} identical sends within 10 minutes; may be intentional",
                       evidence={"fingerprint": act.fingerprint[:16]})


def decide_approval(db, org: Organization, approval: Approval, user, role: str, approve: bool, note: str | None) -> dict:
    if not role_at_least(role, approval.required_role):
        raise HTTPException(403, f"Approval requires {approval.required_role} role or higher")
    # Atomic state change: a repeated or concurrent approval cannot execute the action twice.
    new_status = "approved" if approve else "rejected"
    n = db.execute(update(Approval).where(Approval.id == approval.id, Approval.status == "pending")
                   .values(status=new_status, decided_by=user.id, decided_at=utcnow(), note=note)).rowcount
    if n != 1:
        db.rollback()
        raise HTTPException(409, "Approval has already been decided")
    db.refresh(approval)
    act = db.get(ActionRequest, approval.action_id)
    actor = f"user:{user.email}"
    audit(db, org.id, actor, f"approval.{new_status}", f"approval:{approval.id}", {"action_id": act.id, "note": note})
    emit(db, org.id, f"approval.{new_status}", trace_id=act.trace_id, resource_type="action", resource_id=act.id, correlation_id=act.id,
         payload={"by": user.email, "note": note})
    inc = db.get(Incident, approval.incident_id) if approval.incident_id else None
    ok = True
    if approve:
        integ, res = resolve_target(db, org.id, act.action_type, act.target)
        current = connectors.read_state(db, integ, act.action_type, res)
        if (org.settings or {}).get("kill_switch"):
            act.status, act.result, ok = "rejected", {"error": "kill_switch"}, False
        elif act.action_type.startswith("ads.") and (act.prior_state or {}).get("daily_budget") != current.get("daily_budget"):
            # State changed since the request was evaluated: the approval no longer reflects reality.
            act.status, act.result, ok = "rejected", {"error": "stale_state", "requested_against": act.prior_state, "current": current}, False
        else:
            ok = _execute(db, org, act, integ, res, act.parameters, actor=actor)
    else:
        act.status = "rejected"
    if inc and inc.status not in ("resolved", "closed"):
        transition(db, inc, "resolved", actor, f"Action {new_status} by {user.email}" + ("" if ok else " (execution failed)"))
    db.commit()
    return serialize(act, approval=new_status)


def serialize(act: ActionRequest, **extra) -> dict:
    return {"action_id": act.id, "status": act.status, "decision": act.decision, "action_type": act.action_type,
            "trace_id": act.trace_id, "idempotency_key": act.idempotency_key, "result": act.result, **extra}
