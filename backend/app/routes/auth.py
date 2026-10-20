from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select

from ..config import settings
from ..core import audit
from ..db import get_db, utcnow
from ..deps import ROLES, Ctx, current_user, get_ctx, rate_limit, require
from ..models import Membership, Organization, Session, User, to_dict
from ..security import create_token, hash_password, verify_password, verify_turnstile

router = APIRouter(prefix="/v1", tags=["auth & organizations"])


class Register(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=200)
    name: str = Field("", max_length=200)
    organization_name: str = Field(min_length=1, max_length=200)
    turnstile_token: str | None = None


class Login(BaseModel):
    email: EmailStr
    password: str = Field(max_length=200)
    turnstile_token: str | None = None


def _human(token: str | None, action: str):
    if settings.turnstile_secret and not verify_turnstile(token, action):
        raise HTTPException(403, "Human verification failed. Please try again.")


@router.get("/auth/config")
def auth_config():
    """Public: what the sign-in page needs to render (Turnstile sitekey, if enabled)."""
    return {"turnstile_sitekey": settings.turnstile_sitekey if settings.turnstile_secret else None}


def _session(db, user: User) -> dict:
    sess = Session(user_id=user.id, expires_at=utcnow() + timedelta(hours=settings.session_hours))
    db.add(sess)
    db.commit()
    return {"token": create_token(user.id, sess.id), "expires_at": sess.expires_at, "user": to_dict(user), "organizations": _orgs(db, user)}


def _orgs(db, user: User) -> list[dict]:
    rows = db.execute(select(Organization, Membership.role).join(Membership, Membership.organization_id == Organization.id)
                      .where(Membership.user_id == user.id).order_by(Organization.created_at)).all()
    return [{"id": o.id, "name": o.name, "plan": o.plan, "role": r} for o, r in rows]


@router.post("/auth/register", status_code=201)
def register(body: Register, db=Depends(get_db)):
    rate_limit(f"register:{body.email.lower()}", 5)
    _human(body.turnstile_token, "signup")
    if db.scalar(select(User.id).where(User.email == body.email.lower())):
        raise HTTPException(409, "An account with this email already exists")
    user = User(email=body.email.lower(), name=body.name, password_hash=hash_password(body.password))
    org = Organization(name=body.organization_name)
    db.add_all([user, org])
    db.flush()
    db.add(Membership(organization_id=org.id, user_id=user.id, role="owner"))
    audit(db, org.id, f"user:{user.email}", "organization.created", f"organization:{org.id}", {"name": org.name})
    return _session(db, user)


@router.post("/auth/login")
def login(body: Login, db=Depends(get_db)):
    rate_limit(f"login:{body.email.lower()}", 10)
    _human(body.turnstile_token, "login")
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not verify_password(body.password, user.password_hash) or user.status != "active":
        raise HTTPException(401, "Invalid email or password")
    return _session(db, user)


@router.post("/auth/logout")
def logout(auth=Depends(current_user), db=Depends(get_db)):
    sess = db.get(Session, auth[1])
    sess.revoked_at = utcnow()
    db.commit()
    return {"ok": True}


@router.post("/auth/sessions/revoke-all")
def revoke_all(auth=Depends(current_user), db=Depends(get_db)):
    for s in db.scalars(select(Session).where(Session.user_id == auth[0].id, Session.revoked_at.is_(None))):
        s.revoked_at = utcnow()
    db.commit()
    return {"ok": True}


@router.get("/auth/me")
def me(auth=Depends(current_user), db=Depends(get_db)):
    return {"user": to_dict(auth[0]), "organizations": _orgs(db, auth[0])}


class OrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


@router.post("/organizations", status_code=201)
def create_org(body: OrgCreate, auth=Depends(current_user), db=Depends(get_db)):
    user = auth[0]
    org = Organization(name=body.name)
    db.add(org)
    db.flush()
    db.add(Membership(organization_id=org.id, user_id=user.id, role="owner"))
    audit(db, org.id, f"user:{user.email}", "organization.created", f"organization:{org.id}", {"name": org.name})
    db.commit()
    return to_dict(org)


@router.get("/organizations/{org_id}")
def get_org(org_id: str, ctx: Ctx = Depends(get_ctx)):
    if ctx.org.id != org_id:
        raise HTTPException(404, "Organization not found")
    return to_dict(ctx.org, role=ctx.role)


class OrgSettings(BaseModel):
    name: str | None = Field(None, max_length=200)
    retention_days: int | None = Field(None, ge=7, le=730)
    notify_webhook_url: str | None = Field(None, max_length=500)
    kill_switch: bool | None = None
    detectors: dict[str, float] | None = None


@router.patch("/organizations/{org_id}")
def update_org(org_id: str, body: OrgSettings, ctx: Ctx = Depends(require("admin"))):
    from ..detection import DEFAULTS
    from ..security import check_url_safe

    if ctx.org.id != org_id:
        raise HTTPException(404, "Organization not found")
    s = dict(ctx.org.settings or {})
    changes = body.model_dump(exclude_none=True)
    if "name" in changes:
        ctx.org.name = changes.pop("name")
    if changes.get("notify_webhook_url"):
        try:
            check_url_safe(changes["notify_webhook_url"])
        except ValueError as e:
            raise HTTPException(422, str(e))
    if "detectors" in changes:
        bad = set(changes["detectors"]) - set(DEFAULTS)
        if bad:
            raise HTTPException(422, f"Unknown detector settings: {', '.join(sorted(bad))}")
        changes["detectors"] = {**s.get("detectors", {}), **changes["detectors"]}
    s.update(changes)
    ctx.org.settings = s
    audit(ctx.db, ctx.org.id, ctx.actor, "organization.settings_changed", f"organization:{ctx.org.id}", changes)
    ctx.db.commit()
    return to_dict(ctx.org)


@router.get("/members")
def members(ctx: Ctx = Depends(get_ctx)):
    rows = ctx.db.execute(select(Membership, User).join(User, User.id == Membership.user_id)
                          .where(Membership.organization_id == ctx.org.id)).all()
    return [{"id": m.id, "user_id": u.id, "email": u.email, "name": u.name, "role": m.role, "status": u.status} for m, u in rows]


class MemberAdd(BaseModel):
    email: EmailStr
    role: str
    temporary_password: str | None = Field(None, min_length=10, max_length=200)


@router.post("/members", status_code=201)
def add_member(body: MemberAdd, ctx: Ctx = Depends(require("admin"))):
    if body.role not in ROLES or (body.role == "owner" and ctx.role != "owner"):
        raise HTTPException(422, "Invalid role")
    user = ctx.db.scalar(select(User).where(User.email == body.email.lower()))
    if not user:
        if not body.temporary_password:
            raise HTTPException(422, "New users need a temporary password")
        user = User(email=body.email.lower(), password_hash=hash_password(body.temporary_password))
        ctx.db.add(user)
        ctx.db.flush()
    if ctx.db.scalar(select(Membership.id).where(Membership.organization_id == ctx.org.id, Membership.user_id == user.id)):
        raise HTTPException(409, "Already a member")
    ctx.db.add(Membership(organization_id=ctx.org.id, user_id=user.id, role=body.role))
    audit(ctx.db, ctx.org.id, ctx.actor, "member.added", f"user:{user.email}", {"role": body.role})
    ctx.db.commit()
    return {"ok": True}


class MemberRole(BaseModel):
    role: str


@router.patch("/members/{membership_id}")
def change_role(membership_id: str, body: MemberRole, ctx: Ctx = Depends(require("admin"))):
    m = ctx.db.get(Membership, membership_id)
    if not m or m.organization_id != ctx.org.id:
        raise HTTPException(404, "Member not found")
    if body.role not in ROLES or ("owner" in (body.role, m.role) and ctx.role != "owner"):
        raise HTTPException(403, "Only owners can grant or change the owner role")
    if m.user_id == ctx.user.id:
        raise HTTPException(409, "You cannot change your own role")
    audit(ctx.db, ctx.org.id, ctx.actor, "member.role_changed", f"membership:{m.id}", {"from": m.role, "to": body.role})
    m.role = body.role
    ctx.db.commit()
    return {"ok": True}


@router.delete("/members/{membership_id}")
def remove_member(membership_id: str, ctx: Ctx = Depends(require("admin"))):
    m = ctx.db.get(Membership, membership_id)
    if not m or m.organization_id != ctx.org.id:
        raise HTTPException(404, "Member not found")
    if m.role == "owner" and ctx.role != "owner" or m.user_id == ctx.user.id:
        raise HTTPException(403, "Cannot remove this member")
    audit(ctx.db, ctx.org.id, ctx.actor, "member.removed", f"membership:{m.id}", {})
    ctx.db.delete(m)
    ctx.db.commit()
    return {"ok": True}
