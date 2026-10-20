"""Rule- and baseline-based detectors (no ML until labelled data exists)."""

import statistics
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from .core import emit
from .db import utcnow
from .incidents import raise_incident
from .models import Alert, Campaign, CampaignMetric, Event, Integration, Organization, Workflow

DEFAULTS = {
    "failure_threshold": 2,  # failures within the window that open an incident
    "failure_window_minutes": 60,
    "retry_threshold": 3,
    "slow_multiplier": 3.0,
    "spend_robust_z": 3.5,
    "spend_min_pct_change": 50.0,
    "spend_min_samples": 8,
    "spend_min_amount": 5.0,
    "daily_overspend_ratio": 1.2,
    "heartbeat_multiplier": 2.0,
    "metrics_stale_hours": 4,
    "integration_failure_threshold": 3,
}
EPS = 1e-6


def cfg(org: Organization) -> dict:
    return {**DEFAULTS, **(org.settings or {}).get("detectors", {})}


# --- statistics -------------------------------------------------------------

def zscore(x: float, history: list[float], min_samples: int = 8) -> float | None:
    if len(history) < min_samples:
        return None
    sd = statistics.pstdev(history)
    mean = statistics.fmean(history)
    return (x - mean) / max(sd, abs(mean) * 0.05, EPS)


def robust_z(x: float, history: list[float], min_samples: int = 8) -> float | None:
    """Median/MAD z-score; guards near-zero MAD (flat baselines) and small samples."""
    if len(history) < min_samples:
        return None
    med = statistics.median(history)
    mad = statistics.median(abs(h - med) for h in history) * 1.4826
    return (x - med) / max(mad, abs(med) * 0.05, EPS)


def pct_change(x: float, base: float) -> float | None:
    return None if abs(base) < EPS else (x - base) / abs(base) * 100


def confidence_label(strength: float) -> str:
    """Heuristic (uncalibrated) label from how far past the threshold a signal is."""
    return "high" if strength >= 2 else "medium" if strength >= 1.2 else "low"


# --- workflow detectors -----------------------------------------------------

def on_event(db, org: Organization, ev: Event, wf: Workflow | None):
    c = cfg(org)
    if ev.event_type == "workflow.execution.failed" and wf:
        since = ev.occurred_at - timedelta(minutes=c["failure_window_minutes"])
        fails = db.scalar(
            select(func.count()).select_from(Event).where(
                Event.organization_id == org.id, Event.resource_id == ev.resource_id,
                Event.event_type == "workflow.execution.failed", Event.occurred_at >= since,
            )
        )
        retries = int(ev.payload.get("retry_count") or 0)
        if retries >= c["retry_threshold"]:
            raise_incident(
                db, org, kind="retry_storm", title=f"Retry storm in workflow '{wf.name}'", severity="medium",
                dedup_key=f"retry:{wf.id}", detector="retry_frequency", resource_type="workflow", resource_id=wf.id,
                integration_id=wf.integration_id, message=f"{retries} retries on execution {ev.payload.get('execution_id')}",
                confidence=confidence_label(retries / c["retry_threshold"]),
                evidence={"retry_count": retries, "threshold": c["retry_threshold"]}, event_ids=[ev.id],
            )
        if fails >= c["failure_threshold"] or ev.severity in ("high", "critical"):
            raise_incident(
                db, org, kind="workflow_failure", title=f"Workflow '{wf.name}' is failing",
                severity="critical" if ev.severity == "critical" else "high", dedup_key=f"wf_fail:{wf.id}",
                detector="failure_rate", resource_type="workflow", resource_id=wf.id, integration_id=wf.integration_id,
                message=f"{fails} failed execution(s) in {c['failure_window_minutes']} min; last error: {ev.payload.get('error_type', 'unknown')}",
                confidence=confidence_label(fails / c["failure_threshold"]),
                evidence={"failures_in_window": fails, "threshold": c["failure_threshold"], "error_type": ev.payload.get("error_type")},
                event_ids=[ev.id],
            )
    elif ev.event_type == "workflow.execution.succeeded" and wf and ev.payload.get("duration_ms"):
        recent = db.scalars(
            select(Event.payload).where(
                Event.organization_id == org.id, Event.resource_id == ev.resource_id,
                Event.event_type == "workflow.execution.succeeded", Event.id != ev.id,
            ).order_by(Event.occurred_at.desc()).limit(50)
        ).all()
        durations = [p["duration_ms"] for p in recent if p.get("duration_ms")]
        if len(durations) >= 10 and ev.payload["duration_ms"] > statistics.median(durations) * c["slow_multiplier"]:
            db.add(Alert(organization_id=org.id, detector="duration", resource_type="workflow", resource_id=wf.id,
                         severity="low", confidence="medium", message=f"Execution took {ev.payload['duration_ms']} ms",
                         evidence={"median_ms": statistics.median(durations)}))


def check_heartbeats(db, org: Organization):
    """Missing expected executions for workflows that declare a schedule."""
    c = cfg(org)
    now = utcnow()
    for wf in db.scalars(select(Workflow).where(
        Workflow.organization_id == org.id, Workflow.monitored.is_(True), Workflow.status == "active",
        Workflow.expected_interval_minutes.is_not(None),
    )):
        last = wf.last_execution_at or wf.created_at
        overdue = (now - last).total_seconds() / 60
        limit = wf.expected_interval_minutes * c["heartbeat_multiplier"]
        if overdue > limit:
            raise_incident(
                db, org, kind="missing_heartbeat", title=f"Workflow '{wf.name}' stopped running",
                severity="high" if overdue > limit * 3 else "medium", dedup_key=f"heartbeat:{wf.id}",
                detector="missing_heartbeat", resource_type="workflow", resource_id=wf.id, integration_id=wf.integration_id,
                message=f"No execution for {int(overdue)} min (expected every {wf.expected_interval_minutes} min)",
                confidence=confidence_label(overdue / limit),
                evidence={"last_execution_at": last.isoformat(), "expected_interval_minutes": wf.expected_interval_minutes, "minutes_overdue": int(overdue)},
            )


# --- spend detectors --------------------------------------------------------

def check_spend(db, org: Organization, campaign: Campaign, metric: CampaignMetric):
    c = cfg(org)
    hist = db.scalars(
        select(CampaignMetric).where(
            CampaignMetric.campaign_id == campaign.id, CampaignMetric.bucket_start < metric.bucket_start,
            CampaignMetric.bucket_start >= metric.bucket_start - timedelta(days=14),
        ).order_by(CampaignMetric.bucket_start)
    ).all()
    # Seasonality: compare to the same hour of day when there is enough history.
    same_hour = [m.spend for m in hist if m.bucket_start.hour == metric.bucket_start.hour]
    series = same_hour if len(same_hour) >= c["spend_min_samples"] else [m.spend for m in hist[-48:]]
    freshness = {"data_as_of": metric.bucket_start.isoformat(), "received_at": metric.received_at.isoformat() if metric.received_at else None,
                 "note": "Provider metrics may be delayed or revised"}
    rz = robust_z(metric.spend, series, c["spend_min_samples"])
    if rz is not None:
        med = statistics.median(series)
        pct = pct_change(metric.spend, med)
        if rz >= c["spend_robust_z"] and (pct is None or pct >= c["spend_min_pct_change"]) and metric.spend >= c["spend_min_amount"]:
            raise_incident(
                db, org, kind="spend_anomaly", title=f"Abnormal spend on '{campaign.name}'",
                severity="critical" if rz >= c["spend_robust_z"] * 3 else "high", dedup_key=f"spend:{campaign.id}",
                detector="spend_robust_z", resource_type="campaign", resource_id=campaign.id, integration_id=campaign.integration_id,
                message=f"{campaign.currency} {metric.spend:.2f} in hour vs median {med:.2f} (robust z={rz:.1f})",
                confidence=confidence_label(rz / c["spend_robust_z"]),
                evidence={"observed": metric.spend, "baseline_median": med, "baseline_mean": statistics.fmean(series),
                          "baseline_stdev": statistics.pstdev(series), "robust_z": round(rz, 2),
                          "zscore": round(zscore(metric.spend, series, c["spend_min_samples"]) or 0, 2),
                          "pct_change": round(pct, 1) if pct is not None else None, "samples": len(series),
                          "seasonal": len(same_hour) >= c["spend_min_samples"], **freshness},
            )
    # Fixed threshold: spend today (account time zone) vs daily budget.
    tz = ZoneInfo(campaign.timezone or "UTC")
    day_start = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0)
    today = db.scalar(select(func.coalesce(func.sum(CampaignMetric.spend), 0)).where(
        CampaignMetric.campaign_id == campaign.id, CampaignMetric.bucket_start >= day_start))
    if campaign.daily_budget and today > campaign.daily_budget * c["daily_overspend_ratio"]:
        raise_incident(
            db, org, kind="spend_anomaly", title=f"'{campaign.name}' exceeded its daily budget", severity="high",
            dedup_key=f"spend:{campaign.id}", detector="daily_budget_threshold", resource_type="campaign",
            resource_id=campaign.id, integration_id=campaign.integration_id,
            message=f"Spent {campaign.currency} {today:.2f} today vs budget {campaign.daily_budget:.2f}",
            confidence=confidence_label(today / (campaign.daily_budget * c["daily_overspend_ratio"])),
            evidence={"spend_today": today, "daily_budget": campaign.daily_budget, "ratio": c["daily_overspend_ratio"],
                      "account_timezone": campaign.timezone, **freshness},
        )


def check_metric_freshness(db, org: Organization):
    c = cfg(org)
    cutoff = utcnow() - timedelta(hours=c["metrics_stale_hours"])
    for camp in db.scalars(select(Campaign).where(Campaign.organization_id == org.id, Campaign.status == "enabled")):
        if camp.metrics_as_of and camp.metrics_as_of < cutoff:
            raise_incident(
                db, org, kind="metrics_delayed", title=f"Metrics for '{camp.name}' are delayed", severity="low",
                dedup_key=f"stale:{camp.id}", detector="metric_freshness", resource_type="campaign", resource_id=camp.id,
                integration_id=camp.integration_id, confidence="medium",
                message=f"Latest metrics are from {camp.metrics_as_of.isoformat()}; spend alerts may lag",
                evidence={"metrics_as_of": camp.metrics_as_of.isoformat(), "stale_after_hours": c["metrics_stale_hours"]},
            )


def record_health(db, org: Organization, integ: Integration, ok: bool, detail: str = "", kind: str = ""):
    h = dict(integ.health or {})
    h["last_check_at"] = utcnow().isoformat()
    if ok:
        if h.get("consecutive_failures"):
            emit(db, org.id, "integration.recovered", resource_type="integration", resource_id=integ.id, integration_id=integ.id)
        h.update(consecutive_failures=0, last_error=None, last_ok_at=h["last_check_at"])
        if integ.status in ("degraded", "disconnected", "auth_expired"):
            integ.status = "connected"
    else:
        h["consecutive_failures"] = h.get("consecutive_failures", 0) + 1
        h["last_error"] = detail
        integ.status = "auth_expired" if kind == "auth" else "degraded"
        ev = emit(db, org.id, "integration.check.failed", resource_type="integration", resource_id=integ.id,
                  integration_id=integ.id, severity="medium", payload={"error_type": kind or "unavailable", "detail": detail})
        if kind == "auth" or h["consecutive_failures"] >= cfg(org)["integration_failure_threshold"]:
            integ.status = "auth_expired" if kind == "auth" else "disconnected"
            raise_incident(
                db, org, kind="integration_health", title=f"Integration '{integ.name}' is unavailable", severity="high",
                dedup_key=f"integration:{integ.id}", detector="integration_health", resource_type="integration",
                resource_id=integ.id, integration_id=integ.id, confidence="high", message=detail,
                evidence={"consecutive_failures": h["consecutive_failures"], "error_type": kind}, event_ids=[ev.id],
            )
    integ.health = h
