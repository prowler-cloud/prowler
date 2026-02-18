from datetime import datetime, timezone
from typing import Any

from cartography.config import Config as CartographyConfig
from celery.utils.log import get_task_logger

from api.attack_paths import database as graph_database
from api.db_utils import rls_transaction
from api.models import (
    AttackPathsScan as ProwlerAPIAttackPathsScan,
    Provider as ProwlerAPIProvider,
    StateChoices,
)
from tasks.jobs.attack_paths.config import is_provider_available

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


def starting_attack_paths_scan(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    task_id: str,
    cartography_config: CartographyConfig,
) -> None:
    with rls_transaction(attack_paths_scan.tenant_id):
        attack_paths_scan.task_id = task_id
        attack_paths_scan.state = StateChoices.EXECUTING
        attack_paths_scan.started_at = datetime.now(tz=timezone.utc)
        attack_paths_scan.update_tag = cartography_config.update_tag

        attack_paths_scan.save(
            update_fields=[
                "task_id",
                "state",
                "started_at",
                "update_tag",
            ]
        )


def finish_attack_paths_scan(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    state: StateChoices,
    ingestion_exceptions: dict[str, Any],
) -> None:
    with rls_transaction(attack_paths_scan.tenant_id):
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
    if attack_paths_scan and attack_paths_scan.state not in (
        StateChoices.COMPLETED,
        StateChoices.FAILED,
    ):
        tmp_db_name = graph_database.get_database_name(
            attack_paths_scan.id, temporary=True
        )
        try:
            graph_database.drop_database(tmp_db_name)

        except Exception:
            logger.exception(
                f"Failed to drop temp database {tmp_db_name} during failure handling"
            )

        finish_attack_paths_scan(
            attack_paths_scan,
            StateChoices.FAILED,
            {"global_error": error},
        )
