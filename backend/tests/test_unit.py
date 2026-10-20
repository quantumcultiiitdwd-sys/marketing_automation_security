"""Unit tests for deterministic logic (PRD 16.2, UT-01..UT-08)."""

import pytest

from app import detection, policy
from app.ingestion import classify_error, normalize_n8n
from app.models import Policy
from app.security import check_url_safe, redact, verify_webhook_signature


def _budget_policy(**rules):
    return Policy(id="p1", key="budget", name="Budget", template="budget_protection", version=1, active=True,
                  rules=policy.validate_rules("budget_protection", rules))


def _ctx(proposed, current=500, allowed=("ads.*",), **kw):
    return policy.ActionContext(action_type="ads.campaign.update_budget", parameters={"proposed_daily_budget": proposed, "currency": "USD"},
                                state={"daily_budget": current, "currency": "USD"}, has_idempotency_key=True, agent_id="a1",
                                agent_allowed=list(allowed), **kw)


def test_ut01_increase_below_threshold_allows():
    d = policy.evaluate([_budget_policy()], _ctx(550))
    assert d.decision == policy.ALLOW


def test_ut02_increase_above_threshold_requires_approval():
    d = policy.evaluate([_budget_policy()], _ctx(700))
    assert d.decision == policy.REQUIRE_APPROVAL
    assert d.reasons[0]["rule"] == "max_increase_percent" and d.policy_refs[0]["version"] == 1


def test_budget_boundaries():
    p = _budget_policy()
    assert policy.evaluate([p], _ctx(600)).decision == policy.ALLOW  # exactly +20%
    assert policy.evaluate([p], _ctx(1000, current=990)).decision == policy.ALLOW  # exactly the cap
    assert policy.evaluate([p], _ctx(1000.01, current=990)).decision == policy.REQUIRE_APPROVAL
    assert policy.evaluate([p], _ctx(10, current=0)).decision == policy.REQUIRE_APPROVAL  # from zero = infinite increase
    assert policy.evaluate([p], _ctx(100)).decision == policy.ALLOW  # decreases always fine


def test_deny_beats_approval_and_modify_clamps():
    soft, hard = _budget_policy(), _budget_policy(max_daily_budget=800, max_increase_percent=1000, on_violation="deny")
    hard.key = "hard"
    assert policy.evaluate([soft, hard], _ctx(900)).decision == policy.DENY
    d = policy.evaluate([_budget_policy(on_violation="modify")], _ctx(900))
    assert d.decision == policy.MODIFY and d.modified_parameters["proposed_daily_budget"] == 600


def test_ut03_unauthorized_agent_denied():
    assert policy.evaluate([], _ctx(510, allowed=("outreach.*",))).decision == policy.DENY
    assert policy.evaluate([], _ctx(510, agent_status="suspended")).decision == policy.DENY


def test_unknown_action_denied_by_default():
    ctx = _ctx(1)
    ctx.action_type = "ads.account.delete"
    assert policy.evaluate([], ctx).decision == policy.DENY


def test_currency_mismatch_denied_by_policy():
    p = _budget_policy(currency="EUR")
    assert policy.evaluate([p], _ctx(510)).decision == policy.REQUIRE_APPROVAL
    assert policy.evaluate([p], _ctx(510)).reasons[0]["rule"] == "currency_mismatch"


def test_rate_limit_and_idempotency_policies():
    rl = Policy(id="r", key="rl", name="RL", template="agent_rate_limit", version=1, active=True,
                rules=policy.validate_rules("agent_rate_limit", {"max_actions": 2}))
    assert policy.evaluate([rl], _ctx(510, count_recent=lambda s: 2)).decision == policy.DENY
    assert policy.evaluate([rl], _ctx(510, count_recent=lambda s: 1)).decision == policy.ALLOW
    idem = Policy(id="i", key="idem", name="I", template="idempotency_required", version=1, active=True,
                  rules=policy.validate_rules("idempotency_required", {}))
    ctx = _ctx(510)
    ctx.has_idempotency_key = False
    assert policy.evaluate([idem], ctx).decision == policy.DENY


def test_policy_validation_rejects_bad_rules():
    for rules in ({"max_daily_budget": -1}, {"bogus": 1}, {"on_violation": "allow"}, {"approval_role": "viewer"},
                  {"max_increase_percent": "20"}):
        with pytest.raises(ValueError):
            policy.validate_rules("budget_protection", rules)
    with pytest.raises(ValueError):
        policy.validate_rules("outreach_guard", {"on_violation": "modify"})


def test_robust_stats_guard_small_and_flat_samples():
    assert detection.robust_z(100, [1, 2, 3]) is None  # UT-07: insufficient history -> no conclusion
    flat = [10.0] * 20
    assert detection.robust_z(10, flat) == 0
    assert detection.robust_z(50, flat) > 3.5  # MAD=0 must not divide by zero
    assert detection.robust_z(5, [0.0] * 20) > 0
    assert detection.pct_change(5, 0) is None
    assert detection.zscore(10, [10.0] * 10) == 0


def test_n8n_normalization_and_error_classification():
    ev = normalize_n8n({"id": "42", "workflowId": "7", "status": "error", "retryOf": "41", "startedAt": "2026-10-20T08:00:00Z",
                        "stoppedAt": "2026-10-20T08:00:03Z", "error": {"message": "Request timed out after 30000ms"}}, "int1")
    assert ev["event_type"] == "workflow.execution.failed" and ev["trace_id"] == "n8n-exec-41"
    assert ev["payload"]["error_type"] == "api_timeout" and ev["payload"]["duration_ms"] == 3000
    assert normalize_n8n({"id": 1, "workflowId": 1, "finished": True}, "i")["event_type"] == "workflow.execution.succeeded"
    assert normalize_n8n({"id": 2, "workflowId": 1, "status": "error", "error": "boom"}, "i")["payload"]["error_message"] == "boom"
    assert classify_error("401 Unauthorized") == "auth_error"
    assert classify_error("429 Too Many Requests") == "rate_limited"
    assert classify_error("400 Bad Request: invalid parameter") == "invalid_config"


def test_redaction_and_signatures():
    out = redact({"api_key": "x", "nested": {"Authorization": "y", "note": "mail jane@acme.com"}})
    assert out["api_key"] == "[redacted]" and out["nested"]["Authorization"] == "[redacted]"
    assert "jane" not in out["nested"]["note"] and "@acme.com" in out["nested"]["note"]
    import hashlib
    import hmac
    import time

    ts, body = str(int(time.time())), b'{"a":1}'
    sig = hmac.new(b"s3cret", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature("s3cret", ts, body, sig)
    assert not verify_webhook_signature("s3cret", ts, body + b" ", sig)
    assert not verify_webhook_signature("s3cret", str(int(time.time()) - 3600), body, sig)  # replay


def test_ssrf_guard(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "allow_private_hosts", False)
    for url in ("http://127.0.0.1:5678", "http://169.254.169.254/latest", "http://10.0.0.5", "file:///etc/passwd", "gopher://x"):
        with pytest.raises(ValueError):
            check_url_safe(url)
