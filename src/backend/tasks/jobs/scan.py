import json
import time
from datetime import datetime, timezone

from celery.utils.log import get_task_logger
from prowler.lib.outputs.finding import Finding as ProwlerFinding
from prowler.lib.scan.scan import Scan as ProwlerScan

from api.db_utils import tenant_transaction
from api.models import (
    Provider,
    Scan,
    Finding,
    Resource,
    ResourceTag,
    StatusChoices as FindingStatus,
    StateChoices,
)
from api.utils import initialize_prowler_provider
from api.v1.serializers import ScanTaskSerializer

logger = get_task_logger(__name__)


def _create_finding_delta(
    last_status: FindingStatus | None | str, new_status: FindingStatus | None
) -> Finding.DeltaChoices:
    """
    Determine the delta status of a finding based on its previous and current status.

    Args:
        last_status (FindingStatus | None | str): The previous status of the finding. Can be None or a string representation.
        new_status (FindingStatus | None): The current status of the finding.

    Returns:
        Finding.DeltaChoices: The delta status indicating if the finding is new, changed, or unchanged.
            - Returns `Finding.DeltaChoices.NEW` if `last_status` is None.
            - Returns `Finding.DeltaChoices.CHANGED` if `last_status` and `new_status` are different.
            - Returns `None` if the status hasn't changed.
    """
    if last_status is None:
        return Finding.DeltaChoices.NEW
    return Finding.DeltaChoices.CHANGED if last_status != new_status else None


def _store_finding(
    finding: ProwlerFinding,
    tenant_id: str,
    scan_instance: Scan,
    resource_instance: Resource,
) -> Finding:
    """
    Store a finding in the database, calculate its delta status, and associate it with a resource and scan.

    Args:
        finding (ProwlerFinding): The finding object obtained from the Prowler scan.
        tenant_id (str): The ID of the tenant owning the finding.
        scan_instance (Scan): The scan instance associated with the finding.
        resource_instance (Resource): The resource instance associated with the finding.

    Returns:
        Finding: The newly created or updated Finding instance.

    """
    finding_uid = finding.finding_uid
    status = FindingStatus[finding.status.value] if finding.status is not None else None
    with tenant_transaction(tenant_id):
        most_recent_finding = (
            Finding.objects.filter(uid=finding_uid)
            .order_by("-id")
            .values("status")
            .first()
        )
        last_status = most_recent_finding["status"] if most_recent_finding else None
    delta = _create_finding_delta(last_status, status)
    with tenant_transaction(tenant_id):
        finding_instance = Finding.objects.create(
            tenant_id=tenant_id,
            uid=finding_uid,
            delta=delta,
            status=status,
            status_extended=finding.status_extended,
            severity=finding.severity.value,
            impact=finding.severity.value,
            raw_result=json.loads(finding.json()),
            check_id=finding.check_id,
            scan=scan_instance,
        )
        finding_instance.add_resources([resource_instance])
    return finding_instance


def _store_resources(
    finding: ProwlerFinding, tenant_id: str, provider_instance: Provider
) -> tuple[Resource, tuple[str, str]]:
    """
    Store resource information from a finding, including tags, in the database.

    Args:
        finding (ProwlerFinding): The finding object containing resource information.
        tenant_id (str): The ID of the tenant owning the resource.
        provider_instance (Provider): The provider instance associated with the resource.

    Returns:
        tuple:
            - Resource: The resource instance created or retrieved from the database.
            - tuple[str, str]: A tuple containing the resource UID and region.

    """
    with tenant_transaction(tenant_id):
        resource_instance, _ = Resource.objects.get_or_create(
            tenant_id=tenant_id,
            provider=provider_instance,
            uid=finding.resource_uid,
            region=finding.region,
            service=finding.service_name,
            type=finding.resource_type,
        )
    with tenant_transaction(tenant_id):
        tags = [
            ResourceTag.objects.get_or_create(
                tenant_id=tenant_id, key=key, value=value
            )[0]
            for key, value in finding.resource_tags.items()
        ]
        resource_instance.upsert_or_delete_tags(tags=tags)
    return resource_instance, (resource_instance.uid, resource_instance.region)


def perform_prowler_scan(
    tenant_id: str, scan_id: str, provider_id: str, checks_to_execute: list[str] = None
):
    """
    Perform a scan using Prowler and store the findings and resources in the database.

    Args:
        tenant_id (str): The ID of the tenant for which the scan is performed.
        scan_id (str): The ID of the scan instance.
        provider_id (str): The ID of the provider to scan.
        checks_to_execute (list[str], optional): A list of specific checks to execute. Defaults to None.

    Returns:
        dict: Serialized data of the completed scan instance.

    Raises:
        ValueError: If the provider cannot be connected.

    """
    with tenant_transaction(tenant_id):
        exception = None
        provider_instance = Provider.objects.get(pk=provider_id)
        start_time = time.time()
        unique_resources = set()

        scan_instance = Scan.objects.get(pk=scan_id)
        scan_instance.state = StateChoices.EXECUTING
        scan_instance.started_at = datetime.now(tz=timezone.utc)
        scan_instance.save()
    try:
        with tenant_transaction(tenant_id):
            try:
                prowler_provider = initialize_prowler_provider(provider_instance)
                provider_instance.connected = True
            except Exception as e:
                provider_instance.connected = False
                raise ValueError(
                    f"Provider {provider_instance.provider} is not connected: {e}"
                )
            finally:
                provider_instance.connection_last_checked_at = datetime.now(
                    tz=timezone.utc
                )
                provider_instance.save()

        prowler_scan = ProwlerScan(
            provider=prowler_provider, checks_to_execute=checks_to_execute
        )
        for progress, findings in prowler_scan.scan():
            for finding in findings:
                resource_instance, resource_uid_tuple = _store_resources(
                    finding, tenant_id, provider_instance
                )
                _store_finding(finding, tenant_id, scan_instance, resource_instance)
                unique_resources.add(resource_uid_tuple)
            with tenant_transaction(tenant_id):
                scan_instance.progress = progress
                scan_instance.save()

        scan_instance.state = StateChoices.COMPLETED
    except Exception as e:
        logger.error(f"Error performing scan {scan_id}: {e}")
        exception = e
        scan_instance.state = StateChoices.FAILED
    finally:
        with tenant_transaction(tenant_id):
            scan_instance.duration = time.time() - start_time
            scan_instance.completed_at = datetime.now(tz=timezone.utc)
            scan_instance.unique_resource_count = len(unique_resources)
            scan_instance.save()
        if exception is not None:
            raise exception
        serializer = ScanTaskSerializer(instance=scan_instance)
        return serializer.data
