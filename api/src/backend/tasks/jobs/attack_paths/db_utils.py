from datetime import datetime, timezone
from typing import Any

from cartography.config import Config as CartographyConfig
from celery.utils.log import get_task_logger
from tasks.jobs.attack_paths.config import is_provider_available

from api.attack_paths import database as graph_database
from api.db_utils import rls_transaction
from api.models import AttackPathsScan as ProwlerAPIAttackPathsScan
from api.models import Provider as ProwlerAPIProvider
from api.models import StateChoices

logger = get_task_logger(__name__)


def can_provider_run_attack_paths_scan(tenant_id: str, provider_id: int) -> bool:
    with rls_transaction(tenant_id):
        prowler_api_provider = ProwlerAPIProvider.objects.get(id=provider_id)

    return is_provider_available(prowler_api_provider.provider)


def create_attack_paths_scan(
    tenant_id: str,
    scan_id: str,
    provider_id: int,
) -> ProwlerAPIAttackPathsScan | None:
    if not can_provider_run_attack_paths_scan(tenant_id, provider_id):
        return None

    with rls_transaction(tenant_id):
        # Inherit graph_data_ready from the previous scan for this provider,
        # so queries remain available while the new scan runs.
        previous_data_ready = ProwlerAPIAttackPathsScan.objects.filter(
            tenant_id=tenant_id,
            provider_id=provider_id,
            graph_data_ready=True,
        ).exists()

        attack_paths_scan = ProwlerAPIAttackPathsScan.objects.create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            scan_id=scan_id,
            state=StateChoices.SCHEDULED,
            started_at=datetime.now(tz=timezone.utc),
            graph_data_ready=previous_data_ready,
        )
        attack_paths_scan.save()

    return attack_paths_scan


def retrieve_attack_paths_scan(
    tenant_id: str,
    scan_id: str,
) -> ProwlerAPIAttackPathsScan | None:
    try:
        with rls_transaction(tenant_id):
            attack_paths_scan = ProwlerAPIAttackPathsScan.objects.get(
                scan_id=scan_id,
            )

        return attack_paths_scan

    except ProwlerAPIAttackPathsScan.DoesNotExist:
        return None


def set_attack_paths_scan_task_id(
    tenant_id: str,
    scan_pk: str,
    task_id: str,
) -> None:
    """Persist the Celery `task_id` on the `AttackPathsScan` row.

    Called at dispatch time (when `apply_async` returns) so the row carries
    the task id even while still `SCHEDULED`. This lets the periodic
    cleanup revoke queued messages for scans that never reached a worker.
    """
    with rls_transaction(tenant_id):
        ProwlerAPIAttackPathsScan.objects.filter(id=scan_pk).update(task_id=task_id)


def starting_attack_paths_scan(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    cartography_config: CartographyConfig,
) -> bool:
    """Flip the row from `SCHEDULED` to `EXECUTING` atomically.

    Returns `False` if the row is gone or has already moved past
    `SCHEDULED` (e.g., periodic cleanup raced ahead and marked it
    `FAILED` while the worker message was still in flight).
    """
    with rls_transaction(attack_paths_scan.tenant_id):
        try:
            locked = ProwlerAPIAttackPathsScan.objects.select_for_update().get(
                id=attack_paths_scan.id
            )
        except ProwlerAPIAttackPathsScan.DoesNotExist:
            return False

        if locked.state != StateChoices.SCHEDULED:
            return False

        locked.state = StateChoices.EXECUTING
        locked.started_at = datetime.now(tz=timezone.utc)
        locked.update_tag = cartography_config.update_tag
        locked.save(update_fields=["state", "started_at", "update_tag"])

    # Keep the in-memory object the caller is holding in sync.
    attack_paths_scan.state = locked.state
    attack_paths_scan.started_at = locked.started_at
    attack_paths_scan.update_tag = locked.update_tag
    return True


def _mark_scan_finished(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    state: StateChoices,
    ingestion_exceptions: dict[str, Any],
) -> None:
    """Set terminal fields on a scan. Caller must be inside a transaction."""
    now = datetime.now(tz=timezone.utc)
    duration = (
        int((now - attack_paths_scan.started_at).total_seconds())
        if attack_paths_scan.started_at
        else 0
    )
    attack_paths_scan.state = state
    attack_paths_scan.progress = 100
    attack_paths_scan.completed_at = now
    attack_paths_scan.duration = duration
    attack_paths_scan.ingestion_exceptions = ingestion_exceptions
    attack_paths_scan.save(
        update_fields=[
            "state",
            "progress",
            "completed_at",
            "duration",
            "ingestion_exceptions",
        ]
    )


def finish_attack_paths_scan(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    state: StateChoices,
    ingestion_exceptions: dict[str, Any],
) -> None:
    with rls_transaction(attack_paths_scan.tenant_id):
        _mark_scan_finished(attack_paths_scan, state, ingestion_exceptions)


def update_attack_paths_scan_progress(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    progress: int,
) -> None:
    with rls_transaction(attack_paths_scan.tenant_id):
        attack_paths_scan.progress = progress
        attack_paths_scan.save(update_fields=["progress"])


def set_graph_data_ready(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    ready: bool,
) -> None:
    with rls_transaction(attack_paths_scan.tenant_id):
        attack_paths_scan.graph_data_ready = ready
        attack_paths_scan.save(update_fields=["graph_data_ready"])


def set_provider_graph_data_ready(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    ready: bool,
) -> None:
    """
    Set `graph_data_ready` for ALL scans of the same provider.

    Used before drop/sync so that older scan IDs cannot bypass the query gate while the graph is being replaced.
    """
    with rls_transaction(attack_paths_scan.tenant_id):
        ProwlerAPIAttackPathsScan.objects.filter(
            tenant_id=attack_paths_scan.tenant_id,
            provider_id=attack_paths_scan.provider_id,
        ).update(graph_data_ready=ready)
        attack_paths_scan.refresh_from_db(fields=["graph_data_ready"])


def recover_graph_data_ready(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> None:
    """
    Best-effort recovery of `graph_data_ready` after a scan failure.

    Queries Neo4j to check if the provider still has data in the tenant
    database. If data exists, restores `graph_data_ready=True` for all scans
    of this provider. Never raises.

    Trade-off: if the worker crashed mid-sync, partial data may exist and
    this will re-enable queries against it. We accept that because leaving
    `graph_data_ready=False` permanently (blocking all queries until the
    next successful scan) is a worse outcome for the user.
    """
    try:
        tenant_db = graph_database.get_database_name(attack_paths_scan.tenant_id)
        if graph_database.has_provider_data(
            tenant_db, str(attack_paths_scan.provider_id)
        ):
            set_provider_graph_data_ready(attack_paths_scan, True)
            logger.info(
                f"Recovered `graph_data_ready` for provider {attack_paths_scan.provider_id}"
            )

    except Exception:
        logger.exception(
            f"Failed to recover `graph_data_ready` for provider {attack_paths_scan.provider_id}"
        )


def fail_attack_paths_scan(
    tenant_id: str,
    scan_id: str,
    error: str,
) -> None:
    """
    Mark the `AttackPathsScan` row as `FAILED` unless it's already `COMPLETED` or `FAILED`.
    Used as a safety net when the Celery task fails outside the job's own error handling.
    """
    attack_paths_scan = retrieve_attack_paths_scan(tenant_id, scan_id)
    if not attack_paths_scan:
        return

    tmp_db_name = graph_database.get_database_name(attack_paths_scan.id, temporary=True)
    try:
        graph_database.drop_database(tmp_db_name)
    except Exception:
        logger.exception(
            f"Failed to drop temp database {tmp_db_name} during failure handling"
        )

    with rls_transaction(tenant_id):
        try:
            fresh = ProwlerAPIAttackPathsScan.objects.select_for_update().get(
                id=attack_paths_scan.id
            )
        except ProwlerAPIAttackPathsScan.DoesNotExist:
            return
        if fresh.state in (StateChoices.COMPLETED, StateChoices.FAILED):
            return
        _mark_scan_finished(fresh, StateChoices.FAILED, {"global_error": error})

    recover_graph_data_ready(fresh)
