"""Remediation planning and human-approved execution. Nothing here runs without an authorized user."""

from fastapi import HTTPException
from sqlalchemy import delete, select

from . import gateway, policy
from .connectors import ACTIONS
from .core import audit, notify
from .db import utcnow
from .deps import role_at_least
from .incidents import _activity, transition
from .models import ActionRequest, Agent, Campaign, Incident, Integration, IncidentEvidence, Remediation, Workflow


def _manual(title, description="", reversibility="n/a"):
    return {"title": title, "description": description, "action_type": None, "risk": "low", "reversibility": reversibility}


def _auto(title, action_type, target, parameters=None, description=""):
    meta = ACTIONS[action_type]
    return {"title": title, "description": description, "action_type": action_type, "target": target,
            "parameters": parameters or {}, "risk": meta["risk"], "reversibility": meta["reversible"]}


def plan(db, org, inc: Incident) -> list[Remediation]:
    db.execute(delete(Remediation).where(Remediation.incident_id == inc.id, Remediation.status == "proposed"))
    steps = []
    top = ((inc.rca or {}).get("hypotheses") or [{}])[0]

    if inc.kind == "spend_anomaly" and (camp := db.get(Campaign, inc.resource_id or "")):
        if camp.status == "enabled":
            steps.append(_auto(f"Pause '{camp.name}' to contain spend", "ads.campaign.pause", {"campaign_id": camp.id},
                               description="Stops delivery immediately. Reversible: re-enable after review."))
        last_raise = db.scalars(select(ActionRequest).where(
            ActionRequest.organization_id == org.id, ActionRequest.action_type == "ads.campaign.update_budget",
            ActionRequest.status == "executed", ActionRequest.target["campaign_id"].as_string().in_([camp.id, camp.external_id]),
        ).order_by(ActionRequest.executed_at.desc())).first()
        prior = (last_raise.prior_state or {}).get("daily_budget") if last_raise else None
        if prior is not None and prior < camp.daily_budget:
            steps.append(_auto(f"Restore daily budget to {camp.currency} {prior:.2f}", "ads.campaign.update_budget",
                               {"campaign_id": camp.id}, {"proposed_daily_budget": prior, "currency": camp.currency},
                               description=f"Compensating action for the change made at {last_raise.executed_at:%H:%M} UTC."))
        steps.append(_manual("Review bid strategy and conversion tracking before re-enabling"))

    elif inc.kind == "policy_violation":
        action_id = next((e.data.get("action_id") for e in db.scalars(select(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id))
                          if e.data.get("action_id")), None)
        act = db.get(ActionRequest, action_id) if action_id else None
        agent = db.get(Agent, act.agent_id) if act and act.agent_id else None
        steps.append(_manual("Confirm no downstream change occurred",
                             "The gateway blocked the request before execution; the provider state is unchanged."))
        if agent and agent.status == "active":
            steps.append(_auto(f"Suspend agent '{agent.name}' pending review", "cs.agent.suspend", {"agent_id": agent.id},
                               description="Revokes the agent's ability to act through the gateway. Reversible from Settings."))
        steps.append(_manual("Review the agent's instructions and recent inputs",
                             "Look for untrusted content that may have steered the agent (prompt injection)."))

    elif inc.kind in ("workflow_failure", "retry_storm", "missing_heartbeat") and (wf := db.get(Workflow, inc.resource_id or "")):
        integ = db.get(Integration, wf.integration_id)
        if inc.kind == "missing_heartbeat" and wf.status == "inactive":
            steps.append(_auto(f"Reactivate '{wf.name}'", "n8n.workflow.activate", {"workflow_id": wf.id}))
        elif wf.previous_config and integ.mode == "sandbox" and "configuration" in top.get("cause", "").lower():
            steps.append(_auto(f"Roll back '{wf.name}' to the previous configuration", "n8n.workflow.rollback", {"workflow_id": wf.id},
                               description="Restores the last known-good version. Reversible: the current version is kept."))
        elif wf.status == "active" and inc.kind != "missing_heartbeat":
            steps.append(_auto(f"Deactivate '{wf.name}' to stop repeated failures", "n8n.workflow.deactivate", {"workflow_id": wf.id},
                               description="Prevents further failed runs and retries. Reactivate once the cause is fixed."))
        for s in top.get("next_steps", []):
            steps.append(_manual(s))

    elif inc.kind == "duplicate_action":
        steps.append(_manual("Inspect the original downstream delivery state", "Confirm what recipients actually received."))
        steps.append(_manual("Delivered messages cannot be recalled",
                             "Only send a correction notice if recipients were actually affected.", reversibility="irreversible"))
        for s in top.get("next_steps", []):
            if "delivery state" not in s:
                steps.append(_manual(s))
    else:
        steps += [_manual(s) for s in top.get("next_steps", [])] or [_manual("Investigate manually and record the cause")]

    start = len(db.scalars(select(Remediation.id).where(Remediation.incident_id == inc.id)).all())
    rows = [Remediation(organization_id=org.id, incident_id=inc.id, step=start + i, **{k: v for k, v in s.items()})
            for i, s in enumerate(steps, 1)]
    db.add_all(rows)
    _activity(db, inc, "system", "remediation", {"message": f"{len(rows)} remediation step(s) proposed"})
    db.commit()
    return rows


def execute(db, org, rem: Remediation, user, role: str) -> Remediation:
    if rem.action_type is None:
        raise HTTPException(400, "Manual step: mark it complete instead")
    if rem.status != "proposed":
        raise HTTPException(409, f"Remediation is already {rem.status}")
    required = "admin" if ACTIONS[rem.action_type]["risk"] == "high" else "operator"
    if not role_at_least(role, required):
        raise HTTPException(403, f"Executing this remediation requires {required} role or higher")
    inc = db.get(Incident, rem.incident_id)
    actor = f"user:{user.email}"
    env = gateway.ActionEnvelope(action_type=rem.action_type, target=rem.target, parameters=rem.parameters,
                                 idempotency_key=f"remediation:{rem.id}", trace_id=f"remediation-{inc.id[:8]}")
    decision, integ, res, state = gateway.evaluate_safely(db, org, env, user_role=role)
    if decision.decision == policy.REQUIRE_APPROVAL and not role_at_least(role, decision.approval_role):
        raise HTTPException(403, f"Policy requires approval by {decision.approval_role} or higher")

    act = ActionRequest(organization_id=org.id, actor_user_id=user.id, action_type=env.action_type, target=env.target,
                        parameters=env.parameters, idempotency_key=env.idempotency_key, trace_id=env.trace_id, prior_state=state,
                        fingerprint=gateway.fingerprint(org.id, env.action_type, env.target, env.parameters))
    db.add(act)
    db.flush()  # unique idempotency key: a remediation step can only ever execute once
    gateway._record_decision(db, org, act, decision, env.trace_id)
    rem.action_id, rem.approved_by, rem.approved_at = act.id, user.id, utcnow()
    audit(db, org.id, actor, "remediation.approved", f"remediation:{rem.id}", {"action_type": rem.action_type, "target": rem.target})

    if decision.decision == policy.DENY:
        act.status, rem.status = "denied", "failed"
        rem.verification = {"blocked": True, "reasons": decision.reasons}
        _activity(db, inc, actor, "remediation", {"message": f"Blocked by policy: {rem.title}"})
        db.commit()
        return rem
    if inc.status in ("open", "investigating", "awaiting_approval"):
        transition(db, inc, "mitigating", actor, f"Executing: {rem.title}")
    ok = gateway._execute(db, org, act, integ, res, decision.modified_parameters or env.parameters, actor)
    verified = ok and (act.result or {}).get("verified", False)
    rem.status = "verified" if verified else "failed"
    rem.verification = {"verified": verified, "prior_state": act.prior_state, "result": act.result, "checked_at": utcnow().isoformat()}
    _activity(db, inc, actor, "remediation", {"message": f"{'Verified' if verified else 'FAILED'}: {rem.title}", "action_id": act.id})
    if not verified:
        notify(db, org, f"Remediation failed: {rem.title}", "Recovery could not be verified; escalating for manual handling", "high", f"/incidents/{inc.id}")
        _activity(db, inc, "system", "system", {"message": "Escalated: automated recovery could not be verified"})
    elif not db.scalars(select(Remediation).where(Remediation.incident_id == inc.id, Remediation.status == "proposed",
                                                  Remediation.action_type.is_not(None))).first():
        manual = db.scalars(select(Remediation.title).where(Remediation.incident_id == inc.id, Remediation.status == "proposed")).all()
        note = f"Recovered via '{rem.title}' (state verified)." + (f" Follow-ups: {'; '.join(manual)}" if manual else "")
        transition(db, inc, "resolved", actor, note)
    db.commit()
    return rem


def complete_manual(db, org, rem: Remediation, user, status: str) -> Remediation:
    if rem.status != "proposed":
        raise HTTPException(409, f"Remediation is already {rem.status}")
    rem.status, rem.approved_by, rem.approved_at = status, user.id, utcnow()
    inc = db.get(Incident, rem.incident_id)
    _activity(db, inc, f"user:{user.email}", "remediation", {"message": f"Marked {status}: {rem.title}"})
    audit(db, org.id, f"user:{user.email}", f"remediation.{status}", f"remediation:{rem.id}", {})
    db.commit()
    return rem

