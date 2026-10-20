# Operational runbooks

## Self-monitoring

| Signal | Where |
|---|---|
| API liveness / readiness | `GET /v1/health`, `GET /v1/ready` (DB check) — wire to your load balancer |
| Errors | `SENTRY_DSN`; every error response carries `request_id` (also `X-Request-ID` header) |
| Worker | container healthcheck goes unhealthy after 3 missed/failed cycles (heartbeat file); logs `monitor cycle failed` |
| Provider health | Integrations page; `integration_health` incidents after 3 consecutive failures (or 1 auth failure) |
| Audit integrity | `GET /v1/audit/verify` — alert if `valid: false` |

## Release rollback

1. Re-deploy the previous image tag (deploy hook with `?tag=<previous>`).
2. Migrations are expand-only for MVP; if a release added a migration, the previous code still runs against it. Only `alembic downgrade -1` when the release notes say it is safe.
3. Check `action_requests` with `status IN ('executing','unknown')` — reconcile against the provider manually. **Never** re-run them; rollback must not repeat external actions.
4. `./scripts/smoke.sh`.

## Emergency shutdown (agents misbehaving)

Settings → Organization → **Kill switch**. Every gateway action is denied immediately. It does not affect changes made directly in provider UIs. To stop one agent: Settings → Agents → Suspend.

## Compromised credential

- Agent key: Settings → Agents → Rotate key (old key stops working instantly) or Suspend.
- Ingest key: Integrations → Rotate key.
- Provider credential (n8n key / Google token): Revoke the integration (deletes the stored secret), rotate at the provider, reconnect.
- Server `SECRET_KEY` leak: rotate it — all sessions become invalid and users must log in again.
- `ENCRYPTION_KEY` leak: rotate provider credentials at the source, then reconnect integrations under the new key.

## Provider API outage / quota

The worker backs off exponentially (up to 60 min) and opens an `integration_health` incident. Nothing to do unless it persists. Advertising metrics will be flagged `delayed`/`stale` — don't act on spend data until fresh.

## Policy service degradation

The engine fails closed: errors become DENY with rule `policy_error`. Check API logs by `request_id`; the policy rows themselves are versioned, so a bad edit is reverted with Policies → Version history → Activate.

## Lost webhook events

Ingestion is idempotent on `event_id`, so senders can safely replay. For live n8n, the worker also polls executions, so missed webhooks are backfilled on the next cycle.

## Cross-tenant security incident

1. Engage kill switch for affected orgs; revoke sessions (`POST /v1/auth/sessions/revoke-all` per user, or rotate `SECRET_KEY` for all).
2. Export `audit_records` for the window; verify chain integrity.
3. Notify affected customers per your DPA.

## Backup / restore

Use managed Postgres point-in-time recovery (RPO target 15 min). Restore drill: restore to a new instance → point a staging API at it → `alembic current` → `smoke.sh` → `GET /v1/audit/verify`.
