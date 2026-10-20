"""Deterministic guardrail engine. No LLM output can override a DENY produced here."""

import fnmatch
from dataclasses import dataclass, field
from typing import Callable

from .connectors import ACTIONS
from .deps import ROLES

ALLOW, DENY, REQUIRE_APPROVAL, MODIFY = "ALLOW", "DENY", "REQUIRE_APPROVAL", "MODIFY"
_RANK = {ALLOW: 0, MODIFY: 1, REQUIRE_APPROVAL: 2, DENY: 3}

TEMPLATES = {
    "budget_protection": {
        "name": "Campaign budget protection",
        "description": "Limit single budget increases and absolute daily budgets.",
        "scope": ["ads.campaign.update_budget"],
        "defaults": {"max_increase_percent": 20.0, "max_daily_budget": 1000.0, "currency": "USD",
                     "on_violation": "require_approval", "approval_role": "admin"},
    },
    "agent_rate_limit": {
        "name": "Agent action rate limit",
        "description": "Cap how many actions a single agent can request in a time window.",
        "scope": ["*"],
        "defaults": {"max_actions": 10, "window_seconds": 60, "on_violation": "deny", "approval_role": "admin"},
    },
    "idempotency_required": {
        "name": "Idempotency keys required",
        "description": "Reject actions that can't be de-duplicated safely.",
        "scope": ["*"],
        "defaults": {"on_violation": "deny", "approval_role": "admin"},
    },
    "outreach_guard": {
        "name": "Outreach send guard",
        "description": "Approval for large sends; block embargoed or competitor domains.",
        "scope": ["outreach.email.send"],
        "defaults": {"max_recipients": 25, "blocked_domains": [], "on_violation": "require_approval", "approval_role": "operator"},
    },
    "change_freeze": {
        "name": "Change freeze",
        "description": "Emergency stop: block matching actions for every agent.",
        "scope": ["*"],
        "defaults": {"actions": ["ads.*"], "on_violation": "deny", "approval_role": "admin"},
    },
}
VIOLATION_OUTCOMES = {"deny": DENY, "require_approval": REQUIRE_APPROVAL, "modify": MODIFY}


def validate_rules(template: str, rules: dict) -> dict:
    if template not in TEMPLATES:
        raise ValueError(f"Unknown template '{template}'")
    defaults = TEMPLATES[template]["defaults"]
    unknown = set(rules) - set(defaults)
    if unknown:
        raise ValueError(f"Unknown parameters: {', '.join(sorted(unknown))}")
    merged = {**defaults, **rules}
    for k, default in defaults.items():
        v = merged[k]
        if isinstance(default, (int, float)) and not isinstance(default, bool):
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0:
                raise ValueError(f"'{k}' must be a non-negative number")
        elif isinstance(default, list) and not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
            raise ValueError(f"'{k}' must be a list of strings")
        elif isinstance(default, str) and not isinstance(v, str):
            raise ValueError(f"'{k}' must be a string")
    allowed = {"deny", "require_approval"} | ({"modify"} if template == "budget_protection" else set())
    if merged["on_violation"] not in allowed:
        raise ValueError(f"on_violation must be one of {sorted(allowed)}")
    if merged["approval_role"] not in ROLES[1:]:
        raise ValueError("approval_role must be analyst, operator, admin or owner")
    return merged


@dataclass
class ActionContext:
    action_type: str
    parameters: dict
    state: dict  # current resource state from the provider
    has_idempotency_key: bool
    agent_id: str | None = None
    agent_allowed: list = field(default_factory=list)
    agent_status: str = "active"
    user_role: str | None = None
    kill_switch: bool = False
    count_recent: Callable[[int], int] = lambda seconds: 0


@dataclass
class Decision:
    decision: str
    reasons: list
    policy_refs: list
    approval_role: str = "admin"
    modified_parameters: dict | None = None

    def as_dict(self):
        return {"decision": self.decision, "reasons": self.reasons, "policy_refs": self.policy_refs,
                "approval_role": self.approval_role, "modified_parameters": self.modified_parameters}


def _reason(rule, message, outcome, policy=None):
    r = {"rule": rule, "message": message, "outcome": outcome}
    if policy is not None:
        r.update(policy=policy.key, version=policy.version)
    return r


def _check(p, ctx: ActionContext) -> tuple[str, str] | None:
    """Return (rule, message) if this policy is violated."""
    r = p.rules
    if p.template == "budget_protection":
        proposed = float(ctx.parameters["proposed_daily_budget"])
        current = float(ctx.state.get("daily_budget") or 0)
        currency = ctx.parameters.get("currency") or ctx.state.get("currency")
        if currency != r["currency"]:
            # ponytail: no FX conversion; policies are per-currency. Add rates when multi-currency accounts appear.
            return "currency_mismatch", f"Policy limits are in {r['currency']}, action is in {currency}"
        if proposed > r["max_daily_budget"]:
            return "max_daily_budget", f"Proposed {proposed:.2f} exceeds max daily budget {r['max_daily_budget']:.2f}"
        if proposed > current:
            pct = float("inf") if current <= 0 else (proposed - current) / current * 100
            if pct > r["max_increase_percent"]:
                return "max_increase_percent", f"Increase of {pct:.0f}% exceeds {r['max_increase_percent']:.0f}% limit (current {current:.2f})"
    elif p.template == "agent_rate_limit" and ctx.agent_id:
        n = ctx.count_recent(int(r["window_seconds"]))
        if n >= r["max_actions"]:
            return "rate_limit", f"Agent made {n} requests in {r['window_seconds']}s (limit {r['max_actions']})"
    elif p.template == "idempotency_required" and not ctx.has_idempotency_key:
        return "idempotency_key_missing", "Action has no idempotency key"
    elif p.template == "outreach_guard":
        recipients = ctx.parameters.get("recipients", [])
        blocked = {d.lower() for d in r["blocked_domains"]}
        hit = sorted({e.split("@")[-1].lower() for e in recipients if e.split("@")[-1].lower() in blocked})
        if hit:
            return "blocked_domain", f"Recipients include blocked domains: {', '.join(hit)}"
        if len(recipients) > r["max_recipients"]:
            return "max_recipients", f"{len(recipients)} recipients exceeds {r['max_recipients']}"
    elif p.template == "change_freeze":
        if any(fnmatch.fnmatch(ctx.action_type, pat) for pat in r["actions"]):
            return "change_freeze", "A change freeze is active for this action"
    return None


def evaluate(policies: list, ctx: ActionContext) -> Decision:
    meta = ACTIONS.get(ctx.action_type)
    if not meta:
        return Decision(DENY, [_reason("unknown_action", f"Unknown action type '{ctx.action_type}' (default deny)", DENY)], [])
    if ctx.kill_switch:
        return Decision(DENY, [_reason("kill_switch", "Organization kill switch is engaged", DENY)], [])
    if ctx.agent_id:
        if ctx.agent_status != "active":
            return Decision(DENY, [_reason("agent_suspended", "Agent is suspended", DENY)], [])
        if ctx.action_type.startswith("cs.") or not any(fnmatch.fnmatch(ctx.action_type, a) for a in ctx.agent_allowed):
            return Decision(DENY, [_reason("agent_permission", f"Agent is not permitted to perform {ctx.action_type}", DENY)], [])

    decision, reasons, refs, approval_role, modified = ALLOW, [], [], "operator", None
    for p in policies:
        if not p.active or not any(fnmatch.fnmatch(ctx.action_type, s) for s in TEMPLATES[p.template]["scope"]):
            continue
        refs.append({"policy": p.key, "version": p.version, "id": p.id})
        violation = _check(p, ctx)
        if not violation:
            reasons.append(_reason("passed", f"{p.name}: passed", ALLOW, p))
            continue
        outcome = VIOLATION_OUTCOMES[p.rules["on_violation"]]
        if outcome == MODIFY and violation[0] in ("max_increase_percent", "max_daily_budget"):
            current = float(ctx.state.get("daily_budget") or 0)
            cap = min(p.rules["max_daily_budget"], current * (1 + p.rules["max_increase_percent"] / 100))
            modified = {**ctx.parameters, "proposed_daily_budget": round(cap, 2)}
        elif outcome == MODIFY:
            outcome = REQUIRE_APPROVAL
        reasons.append(_reason(violation[0], violation[1], outcome, p))
        if _RANK[outcome] > _RANK[decision]:
            decision = outcome
        if outcome == REQUIRE_APPROVAL and ROLES.index(p.rules["approval_role"]) > ROLES.index(approval_role):
            approval_role = p.rules["approval_role"]

    if decision == ALLOW and not reasons:
        reasons.append(_reason("no_policy", "No policy applies; action permitted for this agent", ALLOW))
    if decision != MODIFY:
        modified = None
    return Decision(decision, reasons, refs, approval_role, modified)
