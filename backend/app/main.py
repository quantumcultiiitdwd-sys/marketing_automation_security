import logging
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .config import settings
from .db import SessionLocal
from .routes import auth, dashboard, guardrails, incidents, resources

settings.validate()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("campaignshield")

if settings.sentry_dsn:
    import sentry_sdk

    sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.env, send_default_pii=False)

app = FastAPI(
    title="CampaignShield API",
    version="1.0.0",
    description="Reliability, guardrails and incident investigation for marketing automation.",
    docs_url="/docs",
    openapi_url="/openapi.json",
)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"],
                   allow_headers=["*"], expose_headers=["X-Request-ID"])


@app.middleware("http")
async def request_context(request: Request, call_next):
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _error(request: Request, status: int, code: str, message, details=None):
    body = {"error": {"code": code, "message": message, "request_id": getattr(request.state, "request_id", None)}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(body, status_code=status)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    codes = {400: "bad_request", 401: "unauthenticated", 403: "forbidden", 404: "not_found", 409: "conflict",
             413: "payload_too_large", 422: "invalid_request", 429: "rate_limited"}
    return _error(request, exc.status_code, codes.get(exc.status_code, "error"), exc.detail)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    details = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
    return _error(request, 422, "invalid_request", "Request validation failed", details)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error request_id=%s", getattr(request.state, "request_id", None))
    return _error(request, 500, "internal_error", "Something went wrong")


for r in (auth.router, resources.router, guardrails.router, incidents.router, dashboard.router):
    app.include_router(r)


@app.get("/v1/health", tags=["ops"])
def health():
    return {"status": "ok"}


@app.get("/v1/ready", tags=["ops"])
def ready():
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
    return {"status": "ready", "database": "ok"}
