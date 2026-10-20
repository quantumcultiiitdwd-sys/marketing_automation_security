"""Scheduler/worker: integration health, provider sync, heartbeats, freshness, retention, reconciliation.

Run exactly one replica (`python -m app.worker`).
ponytail: single scheduler loop; add a Postgres advisory lock or a real queue before scaling workers horizontally.
"""

import logging
import signal
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select, update

from . import connectors, detection
from .config import settings
from .connectors import ProviderError
from .db import SessionLocal, utcnow
from .models import ActionRequest, Event, Integration, Organization, QuarantinedEvent

log = logging.getLogger("campaignshield.worker")
_stop = False
HEARTBEAT = Path(tempfile.gettempdir()) / "campaignshield-worker-heartbeat"


def run_once():
    with SessionLocal() as db:
        for org in db.scalars(select(Organization)).all():
            for integ in db.scalars(select(Integration).where(Integration.organization_id == org.id, Integration.status != "revoked")).all():
                backoff = (integ.health or {}).get("backoff_until")
                if backoff and datetime.fromisoformat(backoff) > utcnow():
                    continue
                try:
                    connectors.health(db, integ)
                    connectors.sync(db, org, integ)
                    detection.record_health(db, org, integ, True)
                except ProviderError as e:
                    db.rollback()
                    detection.record_health(db, org, integ, False, e.detail, e.kind)
                    if e.kind in ("quota", "unavailable", "timeout"):
                        n = integ.health.get("consecutive_failures", 1)
                        integ.health = {**integ.health, "backoff_until": (utcnow() + timedelta(minutes=min(2 ** n, 60))).isoformat()}
                except Exception:
                    db.rollback()
                    log.exception("sync failed for integration %s", integ.id)
                db.commit()
            detection.check_heartbeats(db, org)
            detection.check_metric_freshness(db, org)
            cutoff = utcnow() - timedelta(days=int((org.settings or {}).get("retention_days", 90)))
            db.execute(delete(Event).where(Event.organization_id == org.id, Event.received_at < cutoff))
            db.execute(delete(QuarantinedEvent).where(QuarantinedEvent.organization_id == org.id, QuarantinedEvent.received_at < cutoff))
            # A crash between "executing" and the provider response leaves the outcome unknown: flag it, never re-run it.
            db.execute(update(ActionRequest).where(ActionRequest.organization_id == org.id, ActionRequest.status == "executing",
                                                   ActionRequest.created_at < utcnow() - timedelta(minutes=10)).values(status="unknown"))
            db.commit()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    def stop(*_):
        global _stop
        _stop = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info("worker started; interval=%ss", settings.monitor_interval_seconds)
    while not _stop:
        started = time.monotonic()
        try:
            run_once()
            HEARTBEAT.touch()  # docker-compose healthcheck: unhealthy after 3 missed or failed cycles
        except Exception:
            log.exception("monitor cycle failed")
        while not _stop and time.monotonic() - started < settings.monitor_interval_seconds:
            time.sleep(1)


if __name__ == "__main__":
    main()
