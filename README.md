# CampaignShield

A reliability, guardrail and incident-investigation layer for marketing automation. It sits next to n8n, Google Ads and AI agents. It predicts failures, blocks unsafe actions, works out what happened, and helps teams recover safely.

```
agents / n8n ──► /v1/actions/execute ──► auth → idempotency → policy engine ──► provider API
                     (gateway)                       │ DENY / REQUIRE_APPROVAL
n8n / Ads ──► /v1/events + worker sync ──► detectors ──► incidents ──► RCA ──► remediation (human-approved)
```

## Quick start (Docker)

```bash
docker compose up --build
open http://localhost:3000        # create an account, then Settings → Demo → "Load sandbox data"
```

API docs are served at http://localhost:8000/docs.

Sandbox mode simulates the n8n, Google Ads and PR-outreach providers inside the database. You can run every PRD scenario without real accounts or real ad spend.

## Local development

```bash
# API
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/alembic upgrade head            # SQLite by default; set DATABASE_URL for Postgres
.venv/bin/uvicorn app.main:app --reload   # :8000
.venv/bin/python -m app.worker            # scheduler: health, sync, heartbeats, retention
.venv/bin/pytest                          # 33 tests (set TEST_DATABASE_URL to run against Postgres)

# Web
cd frontend && npm install && npm run dev # :3000, proxies /api → API_URL (default http://localhost:8000)
```

## Demo scenarios (Settings → Demo)

Each scenario goes through the real ingestion, gateway, detection and RCA code.

| Scenario | Demonstrates |
|---|---|
| Budget guardrail | Agent tries to 5× a budget. The hard ceiling **denies** it before execution, an incident and RCA are created, and you can suspend the agent and verify. This is the PRD §27 final acceptance flow. |
| Budget approval | +50% request goes to **Approvals**. Approving it re-checks state and executes exactly once. |
| Duplicate outreach | A send times out *after* delivery, then the retry with the same idempotency key is **suppressed and reconciled**. Only one delivery happens. |
| Spend spike | A budget is changed outside the gateway and spend spikes. Detected from metrics (robust z-score, same-hour baseline). This is the monitoring-only demo. |
| Silent failure | A workflow stops running after an upstream 503. The missing-heartbeat incident links the outage. |
| Config failure | A bad config change causes repeated 400s. RCA ranks the config change first, and a one-click verified rollback resolves it. |

## Using it for real

**n8n** (Integrations → Add → n8n → Live): base URL plus an n8n API key, stored encrypted. The worker discovers workflows, pulls executions, and detects config drift. Use "Instrumentation workflow" to download an importable Error Trigger workflow that pushes failures in real time. Set `CAMPAIGNSHIELD_INGEST_KEY` in n8n's environment for it.

**Google Ads** (Live): needs `GOOGLE_OAUTH_CLIENT_ID/SECRET` and `GOOGLE_ADS_DEVELOPER_TOKEN` on the server. Add the integration with the customer ID, then click "Connect Google account" (OAuth with a signed, single-use state). It is read-only by default. Gateway mutations (budget, pause) only turn on when "Allow gateway-controlled changes" is checked.

**Agents** call the gateway with their key and never see provider credentials:

```bash
curl -X POST $API/v1/actions/execute -H "Authorization: Bearer csa_..." -H "Content-Type: application/json" -d '{
  "action_type": "ads.campaign.update_budget",
  "target": {"campaign_id": "<id or Google Ads campaign id>"},
  "parameters": {"proposed_daily_budget": 1200, "currency": "USD"},
  "idempotency_key": "budget-change-123"
}'
# → {"decision": "DENY" | "REQUIRE_APPROVAL" | "ALLOW" | "MODIFY", "status": ..., "policy": {reasons, policy_refs}}
```

**Events**: `POST /v1/events` with `X-CampaignShield-Key`. The body can be a canonical event (PRD §8.2), `{"events": [...]}` with up to 500, or `{"n8n": <execution>}`. Signed webhooks are optional and can be made mandatory per integration. Use `X-CS-Timestamp` and `X-CS-Signature: hex(HMAC-SHA256(secret, "{ts}.{body}"))`. The replay window is 5 minutes.

## Deploying

Images: `backend/Dockerfile` (API and worker share one image) and `frontend/Dockerfile` (Next.js standalone). Both run as non-root and have healthchecks.

1. Provision managed Postgres 16, then set the variables in `.env.example` from your secret manager (`APP_ENV=production` refuses to start without `SECRET_KEY` and `ENCRYPTION_KEY` or on SQLite).
2. Run `alembic upgrade head` once per release (the `migrate` service in compose).
3. Run the `api` (`uvicorn`), **exactly one** `worker` (`python -m app.worker`) and `web` (`API_URL` pointing at the API). Put HTTPS in front of both public services.
4. `./scripts/smoke.sh https://api… https://app…`, and on staging (demo enabled, never production) `python3 scripts/e2e.py https://app… https://api…` for the full end-to-end flow.

CI (`.github/workflows/ci.yml`) runs ruff, the tests on Postgres and SQLite, `alembic check`, OpenAPI validation, pip-audit, the Next build/typecheck, npm audit, gitleaks, a Trivy image scan, and a compose smoke test plus `scripts/e2e.py` against the running containers. `deploy.yml` pushes images to GHCR, then deploys staging and runs smoke tests. Production waits behind a GitHub environment approval, then smoke tests run again. Deploys go through any platform deploy hook (Render, Railway, Fly, Cloud Run, …).

Rollback and operations: see [docs/RUNBOOKS.md](docs/RUNBOOKS.md).

## Security model (summary)

- Tenant isolation is enforced on every query. Cross-tenant reads return 404 with no metadata. RBAC has 5 roles: owner > admin > operator > analyst > viewer.
- Credentials are Fernet-encrypted. API, ingest and agent keys are stored only as SHA-256 hashes and shown once. Sessions are server-side and revocable.
- The policy engine fails closed. Unknown actions, unpermitted agents, policy errors and currency mismatches are all **DENY**. LLM output never feeds the decision.
- Idempotency is a database unique constraint, so concurrent retries execute once. Timeouts become `unknown` and are reconciled, never blindly re-run. Approvals use an atomic `pending→approved` transition and re-check state, so stale approvals are rejected.
- The audit log is append-only and hash-chained (`GET /v1/audit/verify`). Secrets and email addresses are redacted or pseudonymised before storage.
- There is an SSRF guard on user-supplied URLs (private and metadata IPs are blocked in production), plus payload limits, rate limits and security headers.

## Deliberate MVP simplifications

These are marked `ponytail:` in the code, so `grep -rn "ponytail:"` lists them.

| PRD item | MVP choice | Upgrade when |
|---|---|---|
| Redis Streams + Celery | Inline processing on ingest, plus one scheduler process | Ingest exceeds about 50 events/s sustained, or you need >1 worker |
| Managed OIDC | Built-in email/password with revocable JWT sessions | First enterprise or SSO customer |
| In-process rate limiter | Per-replica sliding window | More than one API replica |
| Terraform | Compose and container images, platform-agnostic deploy hooks | Infra target chosen |
| LLM investigation summaries | Deterministic, evidence-cited summaries only | Evaluation set exists (PRD §16.10) |
| FX conversion | Budget policies are per-currency, mismatches are denied | Multi-currency accounts |

Not verified against live provider APIs in this build: the Google Ads REST/OAuth path and the n8n live sync. They are implemented to the public API docs, and the version is configurable via `GOOGLE_ADS_API_VERSION`. Validate both with a test account before the pilot.
