"""Periodic reaper for orphaned temp Neo4j scan databases.

`scan.py` creates a throw-away `db-tmp-scan-<attack_paths_scan_id>` database per
scan and drops it once the scan finishes, success or failure. When the worker
or Neo4j itself dies mid-scan, that drop never runs and nothing else ever
revisits the database - it sits there forever. This sweep lists every temp
database on the ingest cluster and drops the ones whose scan is gone or has
been finished for longer than the configured safety margin.
"""

from datetime import UTC, datetime, timedelta

from api.attack_paths import database as graph_database
from api.db_router import MainRouter
from api.models import AttackPathsScan, StateChoices
from api.uuid_utils import datetime_from_uuid7
from celery.utils.log import get_task_logger
from config.django.base import ATTACK_PATHS_TMP_DB_REAP_SAFETY_MARGIN_HOURS
from uuid6 import UUID as UUID7

logger = get_task_logger(__name__)

TERMINAL_STATES = (
    StateChoices.COMPLETED,
    StateChoices.FAILED,
    StateChoices.CANCELLED,
)


def reap_orphaned_tmp_databases() -> dict:
    """Drop temp Neo4j scan databases whose scan is gone or long finished.

    A failure listing databases aborts the whole sweep (nothing to iterate).
    A failure reaping one database is logged and skipped so the rest of the
    sweep still runs.
    """
    now = datetime.now(tz=UTC)
    safety_margin = timedelta(hours=ATTACK_PATHS_TMP_DB_REAP_SAFETY_MARGIN_HOURS)

    try:
        databases = graph_database.list_databases()
    except Exception:
        logger.exception("Failed to list ingest Neo4j databases for temp-db reap")
        return {"dropped_count": 0, "databases": []}

    tmp_databases = [
        name for name in databases if name.startswith(graph_database.TEMP_DB_PREFIX)
    ]

    dropped: list[str] = []
    for database in tmp_databases:
        try:
            if _is_orphaned(database, now, safety_margin):
                graph_database.drop_database(database)
                dropped.append(database)
                logger.info(f"Dropped orphaned temp Neo4j database `{database}`")
        except Exception:
            logger.exception(f"Failed to reap temp Neo4j database `{database}`")

    logger.info(f"Temp Neo4j database reap: {len(dropped)} dropped")
    return {"dropped_count": len(dropped), "databases": dropped}


def _is_orphaned(database: str, now: datetime, safety_margin: timedelta) -> bool:
    """Decide whether a temp database is safe to drop.

    No scan row: the row was hard-deleted (tenant/provider cleanup) or was
    never created. Falls back to the scan id's own UUIDv7 timestamp so a
    database created moments ago is never touched even without a row to check.

    Scan row present: only reapable once it reached a terminal state and has
    been idle past the safety margin, so a scan still legitimately executing
    is never touched.
    """
    scan_id = database[len(graph_database.TEMP_DB_PREFIX) :]

    try:
        scan_uuid = UUID7(scan_id)
    except ValueError:
        logger.warning(
            f"Temp database `{database}` has an unparseable scan id, skipping"
        )
        return False

    # Global sweep with no tenant context: admin_db bypasses RLS on purpose, the same
    # way cleanup_stale_attack_paths_scans finds stale scans across every tenant.
    scan = (
        AttackPathsScan.all_objects.using(MainRouter.admin_db)
        .filter(id=scan_uuid)
        .first()
    )

    if scan is None:
        if scan_uuid.version != 7:
            logger.warning(
                f"Temp database `{database}` has no scan row and a non-UUIDv7 id, "
                "skipping"
            )
            return False
        return now - datetime_from_uuid7(scan_uuid) >= safety_margin

    if scan.state not in TERMINAL_STATES:
        return False

    return now - scan.updated_at >= safety_margin
