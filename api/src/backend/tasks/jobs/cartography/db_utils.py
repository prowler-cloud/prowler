from datetime import datetime, timezone
from typing import Any

from cartography.config import Config as CartographyConfig

from api.db_utils import rls_transaction
from api.models import CartographyScan as ProwlerAPICartographyScan, StateChoices


def create_cartography_scan(
    tenant_id: str,
    scan_id: str,
    task_id: str,
    provider_id: int,
    cartography_config: CartographyConfig,
) -> ProwlerAPICartographyScan:
    with rls_transaction(tenant_id):
        cartography_scan = ProwlerAPICartographyScan.objects.create(
            tenant_id=tenant_id,
            task_id=task_id,
            provider_id=provider_id,
            scan_id=scan_id,
            state=StateChoices.EXECUTING,
            started_at=datetime.now(tz=timezone.utc),
            update_tag=cartography_config.update_tag,
            neo4j_database=cartography_config.neo4j_database,
        )
        cartography_scan.save()

    return cartography_scan


def modify_cartography_scan(
    cartography_scan: ProwlerAPICartographyScan,
    state: StateChoices,
    ingestion_exceptions: dict[str, Any],
) -> None:
    with rls_transaction(cartography_scan.tenant_id):
        now = datetime.now(tz=timezone.utc)
        duration = int((now - cartography_scan.started_at).total_seconds())

        cartography_scan.state = state
        cartography_scan.progress = 100
        cartography_scan.completed_at = now
        cartography_scan.duration = duration
        cartography_scan.ingestion_exceptions = ingestion_exceptions

        cartography_scan.save(
            update_fields=[
                "state",
                "progress",
                "completed_at",
                "duration",
                "ingestion_exceptions",
            ]
        )


def update_cartography_scan_progress(
    cartography_scan: ProwlerAPICartographyScan,
    progress: int,
) -> None:
    with rls_transaction(cartography_scan.tenant_id):
        cartography_scan.progress = progress
        cartography_scan.save(update_fields=["progress"])
