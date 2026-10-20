from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from datetime import timedelta

from sqlalchemy import String, cast, func, select

from .. import gateway, policy
from ..core import audit
from ..db import get_db, utcnow
from ..deps import Ctx, get_agent, get_ctx, owned, require
from ..models import ActionRequest, Agent, Approval, Campaign, Organization, Policy, PolicyDecision, to_dict

router = APIRouter(prefix="/v1", tags=["guardrails"])


@router.get("/policies/templates")
def templates():
    return policy.TEMPLATES


@router.get("/policies")
def list_policies(ctx: Ctx = Depends(get_ctx)):
    rows = ctx.db.scalars(select(Policy).where(Policy.organization_id == ctx.org.id).order_by(Policy.key, Policy.version.desc())).all()
    grouped: dict[str, dict] = {}
    for p in rows:
        g = grouped.setdefault(p.key, {"key": p.key, "name": p.name, "template": p.template, "versions": []})
        g["versions"].append(to_dict(p))
    for g in grouped.values():
        g["active"] = next((v for v in g["versions"] if v["active"]), None)
        g["decisions_7d"] = ctx.db.scalar(select(func.count()).select_from(PolicyDecision).where(
            PolicyDecision.organization_id == ctx.org.id, PolicyDecision.dry_run.is_(False),
            PolicyDecision.created_at >= utcnow() - timedelta(days=7),
            cast(PolicyDecision.policy_refs, String).contains(f'"{g["key"]}"')))
    return list(grouped.values())


class PolicyCreate(BaseModel):
    key: str | None = Field(None, pattern=r"^[a-z0-9_]{3,100}$")
    name: str = Field(min_length=1, max_length=200)
    template: str
    rules: dict = Field(default_factory=dict)
    activate: bool = True


@router.post("/policies", status_code=201)
def create_policy(body: PolicyCreate, ctx: Ctx = Depends(require("admin"))):
    """Creates a policy, or a new version when `key` already exists. Versions are immutable."""
    try:
        rules = policy.validate_rules(body.template, body.rules)
    except ValueError as e:
        raise HTTPException(422, str(e))
    key = body.key or body.template
    latest = ctx.db.scalars(select(Policy).where(Policy.organization_id == ctx.org.id, Policy.key == key).order_by(Policy.version.desc())).first()
    if latest and latest.template != body.template:
        raise HTTPException(409, "A policy with this key uses a different template")
    if body.activate:
        for p in ctx.db.scalars(select(Policy).where(Policy.organization_id == ctx.org.id, Policy.key == key, Policy.active.is_(True))):
            p.active = False
    p = Policy(organization_id=ctx.org.id, key=key, name=body.name, template=body.template, rules=rules,
               version=(latest.version + 1) if latest else 1, active=body.activate, created_by=ctx.user.id)
    ctx.db.add(p)
    ctx.db.flush()
    audit(ctx.db, ctx.org.id, ctx.actor, "policy.version_created", f"policy:{key}@{p.version}", {"rules": rules, "active": body.activate})
    ctx.db.commit()
    return to_dict(p)


@router.post("/policies/{policy_id}/activate")
def activate_policy(policy_id: str, ctx: Ctx = Depends(require("admin"))):
    p = owned(ctx.db, Policy, policy_id, ctx.org.id)
    for other in ctx.db.scalars(select(Policy).where(Policy.organization_id == ctx.org.id, Policy.key == p.key)):
        other.active = other.id == p.id
    audit(ctx.db, ctx.org.id, ctx.actor, "policy.activated", f"policy:{p.key}@{p.version}", {})
    ctx.db.commit()
    return to_dict(p)


@router.post("/policies/{policy_id}/deactivate")
def deactivate_policy(policy_id: str, ctx: Ctx = Depends(require("admin"))):
    p = owned(ctx.db, Policy, policy_id, ctx.org.id)
    p.active = False
    audit(ctx.db, ctx.org.id, ctx.actor, "policy.deactivated", f"policy:{p.key}@{p.version}", {})
    ctx.db.commit()
    return to_dict(p)


class Simulation(BaseModel):
    action: gateway.ActionEnvelope
    agent_id: str | None = None
    draft: PolicyCreate | None = None  # evaluate a not-yet-saved policy in place of its active version


@router.post("/policies/evaluate")
def evaluate(body: Simulation, ctx: Ctx = Depends(require("analyst"))):
    """Dry run: evaluates without executing. Recorded in decision history as dry_run."""
    agent = owned(ctx.db, Agent, body.agent_id, ctx.org.id) if body.agent_id else None
    policies = list(ctx.db.scalars(select(Policy).where(Policy.organization_id == ctx.org.id, Policy.active.is_(True))))
    if body.draft:
        try:
            rules = policy.validate_rules(body.draft.template, body.draft.rules)
        except ValueError as e:
            raise HTTPException(422, str(e))
        key = body.draft.key or body.draft.template
        policies = [p for p in policies if p.key != key] + [
            Policy(id="draft", key=key, name=body.draft.name, template=body.draft.template, rules=rules, version=0, active=True)]
    decision, _, _, state = gateway.evaluate_safely(ctx.db, ctx.org, body.action, agent=agent,
                                                   user_role=None if agent else ctx.role, policies=policies)
    ctx.db.add(PolicyDecision(organization_id=ctx.org.id, action_type=body.action.action_type, decision=decision.decision,
                              reasons=decision.reasons, policy_refs=decision.policy_refs, dry_run=True))
    ctx.db.commit()
    return {"dry_run": True, **decision.as_dict(), "current_state": state}


@router.get("/policies/{key}/preview")
def preview(key: str, ctx: Ctx = Depends(get_ctx)):
    """Resources a policy currently applies to."""
    p = ctx.db.scalars(select(Policy).where(Policy.organization_id == ctx.org.id, Policy.key == key).order_by(Policy.version.desc())).first()
    if not p:
        raise HTTPException(404, "Policy not found")
    if p.template == "budget_protection":
        rows = ctx.db.scalars(select(Campaign).where(Campaign.organization_id == ctx.org.id)).all()
        return [{"resource": f"campaign:{c.id}", "name": c.name, "daily_budget": c.daily_budget, "currency": c.currency,
                 "applies": c.currency == p.rules["currency"],
                 "max_allowed_without_approval": round(min(p.rules["max_daily_budget"], c.daily_budget * (1 + p.rules["max_increase_percent"] / 100)), 2),
                 "note": "Already above the max daily budget" if c.daily_budget > p.rules["max_daily_budget"] else
                 "" if c.currency == p.rules["currency"] else f"Currency {c.currency} is denied by this policy"}
                for c in rows]
    agents = ctx.db.scalars(select(Agent).where(Agent.organization_id == ctx.org.id)).all()
    return [{"resource": f"agent:{a.id}", "name": a.name, "applies": True, "status": a.status} for a in agents]


@router.get("/policies/decisions")
def decisions(ctx: Ctx = Depends(get_ctx), decision: str | None = None, include_dry_run: bool = False,
              limit: int = Query(50, le=200), offset: int = 0):
    q = select(PolicyDecision).where(PolicyDecision.organization_id == ctx.org.id)
    if decision:
        q = q.where(PolicyDecision.decision == decision)
    if not include_dry_run:
        q = q.where(PolicyDecision.dry_run.is_(False))
    rows = ctx.db.scalars(q.order_by(PolicyDecision.created_at.desc()).limit(limit).offset(offset)).all()
    return [to_dict(d) for d in rows]


# --- gateway ----------------------------------------------------------------

@router.post("/actions/execute", tags=["gateway"])
def execute_action(env: gateway.ActionEnvelope, agent: Agent = Depends(get_agent), db=Depends(get_db)):
    """Agent-facing controlled action gateway. Authenticate with `Authorization: Bearer csa_...`."""
    return gateway.submit(db, db.get(Organization, agent.organization_id), env, agent)


@router.get("/actions", tags=["gateway"])
def list_actions(ctx: Ctx = Depends(get_ctx), status: str | None = None, limit: int = Query(50, le=200), offset: int = 0):
    q = select(ActionRequest).where(ActionRequest.organization_id == ctx.org.id)
    if status:
        q = q.where(ActionRequest.status == status)
    rows = ctx.db.scalars(q.order_by(ActionRequest.created_at.desc()).limit(limit).offset(offset)).all()
    names = {a.id: a.name for a in ctx.db.scalars(select(Agent).where(Agent.organization_id == ctx.org.id))}
    return [to_dict(a, agent_name=names.get(a.agent_id)) for a in rows]


@router.get("/actions/{action_id}", tags=["gateway"])
def get_action(action_id: str, ctx: Ctx = Depends(get_ctx)):
    a = owned(ctx.db, ActionRequest, action_id, ctx.org.id)
    decs = ctx.db.scalars(select(PolicyDecision).where(PolicyDecision.action_id == a.id)).all()
    return to_dict(a, decisions=[to_dict(d) for d in decs])


# --- approvals --------------------------------------------------------------

@router.get("/approvals")
def list_approvals(ctx: Ctx = Depends(get_ctx), status: str | None = None):
    q = select(Approval, ActionRequest).join(ActionRequest, ActionRequest.id == Approval.action_id).where(Approval.organization_id == ctx.org.id)
    if status:
        q = q.where(Approval.status == status)
    rows = ctx.db.execute(q.order_by(Approval.created_at.desc()).limit(200)).all()
    return [to_dict(ap, action=to_dict(act)) for ap, act in rows]


class Decide(BaseModel):
    note: str | None = Field(None, max_length=1000)


@router.post("/approvals/{approval_id}/approve")
def approve(approval_id: str, body: Decide | None = None, ctx: Ctx = Depends(require("operator"))):
    ap = owned(ctx.db, Approval, approval_id, ctx.org.id)
    return gateway.decide_approval(ctx.db, ctx.org, ap, ctx.user, ctx.role, True, body.note if body else None)


@router.post("/approvals/{approval_id}/reject")
def reject(approval_id: str, body: Decide | None = None, ctx: Ctx = Depends(require("operator"))):
    ap = owned(ctx.db, Approval, approval_id, ctx.org.id)
    return gateway.decide_approval(ctx.db, ctx.org, ap, ctx.user, ctx.role, False, body.note if body else None)
