import json
import time
from datetime import datetime, timezone

from celery.utils.log import get_task_logger
from prowler.lib.outputs.finding import Finding as ProwlerFinding
from prowler.lib.scan.scan import Scan as ProwlerScan
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider

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
from api.v1.serializers import ScanTaskSerializer
from config.celery import TaskTimeoutError

logger = get_task_logger(__name__)


def store_finding(
    finding: ProwlerFinding,
    tenant_id: str,
    scan_instance: Scan,
    resource_instance: Resource,
) -> Finding:
    with tenant_transaction(tenant_id):
        finding_instance = Finding.objects.create(
            tenant_id=tenant_id,
            delta=Finding.DeltaChoices.NEW,
            status=FindingStatus[finding.status.value],
            status_extended=finding.status_extended,
            severity=finding.severity.value,
            impact=finding.severity.value,
            raw_result=json.loads(finding.json()),
            check_id=finding.check_id,
            scan=scan_instance,
        )
        finding_instance.add_resources([resource_instance])
    return finding_instance


def store_resources(
    finding: ProwlerFinding, tenant_id: str, provider_instance: Provider
) -> tuple[Resource, tuple[str, str]]:
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
    with tenant_transaction(tenant_id):
        exception = None
        provider_instance = Provider.objects.get(pk=provider_id)
        start_time = time.time()
        unique_resources = set()
        # Prevent race conditions
        while not Scan.objects.filter(id=scan_id).exists():
            if time.time() - start_time > 10:
                raise TaskTimeoutError(
                    f"Could not find scan with given id {scan_id} within 10 seconds"
                )
            time.sleep(0.1)
        scan_instance = Scan.objects.get(pk=scan_id)
        scan_instance.state = StateChoices.EXECUTING
        scan_instance.started_at = datetime.now(tz=timezone.utc)
        scan_instance.save()
    try:
        match provider_instance.provider:
            case Provider.ProviderChoices.AWS.value:
                prowler_provider = AwsProvider
            case Provider.ProviderChoices.GCP.value:
                prowler_provider = GcpProvider
            case Provider.ProviderChoices.AZURE.value:
                prowler_provider = AzureProvider
            case Provider.ProviderChoices.KUBERNETES.value:
                prowler_provider = KubernetesProvider
            case _:
                raise ValueError(
                    f"Provider type {provider_instance.provider} not supported"
                )
        with tenant_transaction(tenant_id):
            connection_status = prowler_provider.test_connection(
                raise_on_exception=False
            )
            provider_instance.connected = connection_status.is_connected
            provider_instance.connection_last_checked_at = datetime.now(tz=timezone.utc)
            provider_instance.save()

        if connection_status.is_connected is False:
            raise ValueError(f"Provider {provider_instance.provider} is not connected")

        prowler_scan = ProwlerScan(
            provider=prowler_provider(), checks_to_execute=checks_to_execute or []
        )
        for progress, findings in prowler_scan.scan():
            for finding in findings:
                resource_instance, resource_uid_tuple = store_resources(
                    finding, tenant_id, provider_instance
                )
                store_finding(finding, tenant_id, scan_instance, resource_instance)
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
