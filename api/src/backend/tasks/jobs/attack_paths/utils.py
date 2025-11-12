import traceback

from datetime import datetime, timezone
from typing import Any

from cartography.config import Config as CartographyConfig

from api.db_utils import rls_transaction
from api.models import AttackPathsScan as ProwlerAPIAttackPathsScan, StateChoices


def create_attack_paths_scan(
    tenant_id: str,
    scan_id: str,
    task_id: str,
    provider_id: int,
    cartography_config: CartographyConfig,
) -> ProwlerAPIAttackPathsScan:
    with rls_transaction(tenant_id):
        attack_paths_scan = ProwlerAPIAttackPathsScan.objects.create(
            tenant_id=tenant_id,
            task_id=task_id,
            provider_id=provider_id,
            scan_id=scan_id,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=timezone.utc),
            update_tag=cartography_config.update_tag,
            neo4j_database=cartography_config.neo4j_database,
        )
        attack_paths_scan.save()

    return attack_paths_scan


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


def stringify_exception(exception: Exception, context: str) -> str:
    timestamp = datetime.now(tz=timezone.utc)
    exception_traceback = traceback.TracebackException.from_exception(exception)
    traceback_string = "".join(exception_traceback.format())
    return f"{timestamp} - {context}\n{traceback_string}"
