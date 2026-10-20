import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .config import settings
from .db import get_db, utcnow
from .models import Agent, Membership, Organization, Session, User
from .security import decode_token, sha256

ROLES = ["viewer", "analyst", "operator", "admin", "owner"]


def role_at_least(role: str, minimum: str) -> bool:
    return ROLES.index(role) >= ROLES.index(minimum)


@dataclass
class Ctx:
    db: DbSession
    user: User
    org: Organization
    role: str
    session_id: str

    @property
    def actor(self) -> str:
        return f"user:{self.user.email}"


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    return authorization[7:].strip()


def current_user(authorization: str | None = Header(None), db: DbSession = Depends(get_db)) -> tuple[User, str]:
    try:
        claims = decode_token(_bearer(authorization))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    sess = db.get(Session, claims.get("sid"))
    if not sess or sess.revoked_at or sess.expires_at < utcnow():
        raise HTTPException(401, "Session expired or revoked")
    user = db.get(User, claims["sub"])
    if not user or user.status != "active":
        raise HTTPException(401, "User inactive")
    return user, sess.id


def get_ctx(
    request: Request,
    x_org_id: str | None = Header(None),
    auth=Depends(current_user),
    db: DbSession = Depends(get_db),
) -> Ctx:
    user, sid = auth
    q = select(Membership).where(Membership.user_id == user.id)
    if x_org_id:
        q = q.where(Membership.organization_id == x_org_id)
    m = db.scalars(q.order_by(Membership.created_at)).first()
    if not m:
        # Same response whether the org exists or not: no tenant metadata leaks.
        raise HTTPException(404, "Organization not found")
    rate_limit(f"org:{m.organization_id}")
    return Ctx(db=db, user=user, org=db.get(Organization, m.organization_id), role=m.role, session_id=sid)


def require(min_role: str):
    def dep(ctx: Ctx = Depends(get_ctx)) -> Ctx:
        if not role_at_least(ctx.role, min_role):
            raise HTTPException(403, f"Requires {min_role} role or higher")
        return ctx

    return dep


def get_agent(authorization: str | None = Header(None), db: DbSession = Depends(get_db)) -> Agent:
    agent = db.scalar(select(Agent).where(Agent.key_hash == sha256(_bearer(authorization))))
    if not agent:
        raise HTTPException(401, "Invalid agent credential")
    rate_limit(f"org:{agent.organization_id}")
    return agent


# ponytail: in-process sliding window per replica; move to Redis when running >1 API replica.
_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(bucket: str, limit: int | None = None, window: float = 60.0):
    limit = limit or settings.rate_limit_per_minute
    now = time.monotonic()
    q = _hits[bucket]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Rate limit exceeded")
    q.append(now)


def owned(db: DbSession, model, obj_id: str, org_id: str):
    """Fetch a tenant-owned row; 404 for both missing and foreign rows."""
    obj = db.get(model, obj_id)
    if not obj or getattr(obj, "organization_id", None) != org_id:
        raise HTTPException(404, f"{model.__name__} not found")
    return obj
