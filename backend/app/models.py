import uuid

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, UTCDateTime, utcnow


def uid() -> str:
    return str(uuid.uuid4())


def _id():
    return mapped_column(String(36), primary_key=True, default=uid)


def _org():
    return mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), index=True)


def _ts():
    return mapped_column(UTCDateTime, default=utcnow)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = _id()
    name: Mapped[str] = mapped_column(String(200))
    plan: Mapped[str] = mapped_column(String(20), default="pilot")
    # detectors overrides, retention_days, notify_webhook_url, kill_switch, suppressions
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at = _ts()


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _id()
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at = _ts()


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20))
    created_at = _ts()


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at = mapped_column(UTCDateTime)
    revoked_at = mapped_column(UTCDateTime, nullable=True)
    created_at = _ts()


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    provider: Mapped[str] = mapped_column(String(30))  # n8n | google_ads | outreach
    name: Mapped[str] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(20), default="sandbox")  # sandbox | live
    status: Mapped[str] = mapped_column(String(20), default="connected")  # connected|degraded|disconnected|auth_expired|revoked
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    health: Mapped[dict] = mapped_column(JSON, default=dict)
    ingest_key_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    ingest_key_prefix: Mapped[str | None] = mapped_column(String(16), nullable=True)
    signing_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = _ts()


class IntegrationCredential(Base):
    __tablename__ = "integration_credentials"
    id: Mapped[str] = _id()
    integration_id: Mapped[str] = mapped_column(String(36), ForeignKey("integrations.id", ondelete="CASCADE"), unique=True)
    # Encrypted at rest (Fernet); the key itself lives in the secret manager.
    ciphertext: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(String(500), default="")
    expires_at = mapped_column(UTCDateTime, nullable=True)
    created_at = _ts()


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    name: Mapped[str] = mapped_column(String(200))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    key_prefix: Mapped[str] = mapped_column(String(16))
    allowed_actions: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | suspended
    created_at = _ts()


class Workflow(Base):
    __tablename__ = "workflows"
    __table_args__ = (UniqueConstraint("integration_id", "external_id"),)
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    integration_id: Mapped[str] = mapped_column(String(36), ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(300), default="")
    version: Mapped[str] = mapped_column(String(100), default="1")
    status: Mapped[str] = mapped_column(String(20), default="active")
    monitored: Mapped[bool] = mapped_column(Boolean, default=True)
    expected_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    previous_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_execution_at = mapped_column(UTCDateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    created_at = _ts()


class Campaign(Base):
    __tablename__ = "campaigns"
    __table_args__ = (UniqueConstraint("integration_id", "external_id"),)
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    integration_id: Mapped[str] = mapped_column(String(36), ForeignKey("integrations.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20), default="enabled")
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    daily_budget: Mapped[float] = mapped_column(Float, default=0)
    budget_resource: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_synced_at = mapped_column(UTCDateTime, nullable=True)
    metrics_as_of = mapped_column(UTCDateTime, nullable=True)
    created_at = _ts()


class CampaignMetric(Base):
    __tablename__ = "campaign_metrics"
    __table_args__ = (UniqueConstraint("campaign_id", "bucket_start"),)
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    campaign_id: Mapped[str] = mapped_column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    bucket_start = mapped_column(UTCDateTime)  # hourly bucket, UTC
    spend: Mapped[float] = mapped_column(Float, default=0)
    impressions: Mapped[int] = mapped_column(Integer, default=0)
    clicks: Mapped[int] = mapped_column(Integer, default=0)
    conversions: Mapped[float] = mapped_column(Float, default=0)
    received_at = _ts()


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("organization_id", "event_id"),
        Index("ix_events_org_time", "organization_id", "occurred_at"),
        Index("ix_events_resource", "organization_id", "resource_id"),
    )
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    event_id: Mapped[str] = mapped_column(String(160))
    integration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source: Mapped[str] = mapped_column(String(50))
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    occurred_at = mapped_column(UTCDateTime)
    received_at = _ts()
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    schema_version: Mapped[str] = mapped_column(String(10), default="1.0")


class QuarantinedEvent(Base):
    __tablename__ = "quarantined_events"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    integration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    raw: Mapped[dict] = mapped_column(JSON)
    error: Mapped[str] = mapped_column(Text)
    received_at = _ts()


class ActionRequest(Base):
    __tablename__ = "action_requests"
    # Idempotency is enforced by the database, not just application code.
    __table_args__ = (UniqueConstraint("organization_id", "idempotency_key"),)
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action_type: Mapped[str] = mapped_column(String(100))
    target: Mapped[dict] = mapped_column(JSON, default=dict)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    trace_id: Mapped[str] = mapped_column(String(128), index=True)
    # evaluating|executing|executed|denied|pending_approval|rejected|failed|unknown
    status: Mapped[str] = mapped_column(String(30), default="evaluating")
    decision: Mapped[str | None] = mapped_column(String(30), nullable=True)
    prior_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at = _ts()
    executed_at = mapped_column(UTCDateTime, nullable=True)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("organization_id", "key", "version"),)
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    key: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(200))
    template: Mapped[str] = mapped_column(String(50))
    version: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    rules: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at = _ts()


class PolicyDecision(Base):
    __tablename__ = "policy_decisions"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    action_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(100))
    decision: Mapped[str] = mapped_column(String(30))
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    policy_refs: Mapped[list] = mapped_column(JSON, default=list)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at = _ts()


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    detector: Mapped[str] = mapped_column(String(60))
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    message: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at = _ts()


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    title: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), default="open")
    dedup_key: Mapped[str] = mapped_column(String(300), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    integration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    assignee_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    detected_at = _ts()
    last_seen_at = _ts()
    acknowledged_at = mapped_column(UTCDateTime, nullable=True)
    resolved_at = mapped_column(UTCDateTime, nullable=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    rca: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    __mapper_args__ = {"version_id_col": version}  # optimistic locking


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    id: Mapped[str] = _id()
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    evidence_type: Mapped[str] = mapped_column(String(50))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at = _ts()


class IncidentActivity(Base):
    __tablename__ = "incident_activity"
    id: Mapped[str] = _id()
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    actor: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(30))  # status | comment | assign | feedback | remediation | system
    body: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at = _ts()


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    action_id: Mapped[str] = mapped_column(String(36), ForeignKey("action_requests.id", ondelete="CASCADE"), unique=True)
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(200))
    required_role: Mapped[str] = mapped_column(String(20), default="admin")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    decided_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decided_at = mapped_column(UTCDateTime, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at = _ts()


class Remediation(Base):
    __tablename__ = "remediations"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    step: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    action_type: Mapped[str | None] = mapped_column(String(100), nullable=True)  # None = manual step
    target: Mapped[dict] = mapped_column(JSON, default=dict)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    risk: Mapped[str] = mapped_column(String(20), default="low")
    reversibility: Mapped[str] = mapped_column(String(30), default="reversible")
    status: Mapped[str] = mapped_column(String(20), default="proposed")  # proposed|executed|verified|failed|done|skipped
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_at = mapped_column(UTCDateTime, nullable=True)
    action_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    verification: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at = _ts()


class AuditRecord(Base):
    __tablename__ = "audit_records"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str] = _org()
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(300))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    created_at = _ts()


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = _id()
    organization_id: Mapped[str] = _org()
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="info")
    link: Mapped[str | None] = mapped_column(String(300), nullable=True)
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at = _ts()


SENSITIVE_COLUMNS = {"password_hash", "key_hash", "ciphertext", "signing_secret_enc", "ingest_key_hash"}


def to_dict(obj, **extra) -> dict:
    d = {c.name: getattr(obj, c.name) for c in obj.__table__.columns if c.name not in SENSITIVE_COLUMNS}
    d.update(extra)
    return d
