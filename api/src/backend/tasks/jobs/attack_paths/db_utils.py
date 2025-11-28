from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from cartography.config import Config as CartographyConfig

from api.db_utils import rls_transaction
from api.models import (
    AttackPathsScan as ProwlerAPIAttackPathsScan,
    Provider as ProwlerAPIProvider,
    StateChoices,
)
from tasks.jobs.attack_paths.providers import is_provider_available


def create_attack_paths_scan(
    tenant_id: str,
    scan_id: str,
    provider_id: int,
) -> ProwlerAPIAttackPathsScan | None:
    with rls_transaction(tenant_id):
        prowler_api_provider = ProwlerAPIProvider.objects.get(id=provider_id)

    if not is_provider_available(prowler_api_provider.provider):
        return None

    with rls_transaction(tenant_id):
        attack_paths_scan = ProwlerAPIAttackPathsScan.objects.create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            scan_id=scan_id,
            state=StateChoices.SCHEDULED,
            started_at=datetime.now(tz=timezone.utc),
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
        attack_paths_scan.graph_database = cartography_config.neo4j_database

        attack_paths_scan.save(
            update_fields=[
                "task_id",
                "state",
                "started_at",
                "update_tag",
                "graph_database",
            ]
        )


def finish_attack_paths_scan(
    attack_paths_scan: ProwlerAPIAttackPathsScan,
    state: StateChoices,
    ingestion_exceptions: dict[str, Any],
) -> None:
    with rls_transaction(attack_paths_scan.tenant_id):
        now = datetime.now(tz=timezone.utc)
        duration = int((now - attack_paths_scan.started_at).total_seconds())

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


def get_old_attack_paths_scans(
    tenant_id: str,
    provider_id: str,
    attack_paths_scan_id: str,
) -> list[ProwlerAPIAttackPathsScan]:
    """
    An `old_attack_paths_scan` is any `completed` Attack Paths scan for the same provider,
    with its graph database not deleted, excluding the current Attack Paths scan.
    """

    with rls_transaction(tenant_id):
        completed_scans_qs = (
            ProwlerAPIAttackPathsScan.objects.filter(
                provider_id=provider_id,
                state=StateChoices.COMPLETED,
                is_graph_database_deleted=False,
            )
            .exclude(id=attack_paths_scan_id)
            .all()
        )

        return list(completed_scans_qs)


def update_old_attack_paths_scan(
    old_attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> None:
    with rls_transaction(old_attack_paths_scan.tenant_id):
        old_attack_paths_scan.is_graph_database_deleted = True
        old_attack_paths_scan.save(update_fields=["is_graph_database_deleted"])


def get_provider_graph_database_names(tenant_id: str, provider_id: str) -> list[str]:
    """
    Return existing graph database names for a tenant/provider.

    Note: For accesing the `AttackPathsScan` we need to use `all_objects` manager because the provider is soft-deleted.
    """
    with rls_transaction(tenant_id):
        graph_databases_names_qs = ProwlerAPIAttackPathsScan.all_objects.filter(
            provider_id=provider_id,
            is_graph_database_deleted=False,
        ).values_list("graph_database", flat=True)

        return list(graph_databases_names_qs)
