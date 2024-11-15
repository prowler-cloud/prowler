import time
from copy import deepcopy
from datetime import datetime, timezone

from celery.utils.log import get_task_logger
from prowler.lib.outputs.finding import Finding as ProwlerFinding
from prowler.lib.scan.scan import Scan as ProwlerScan

from api.compliance import (
    PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE,
    generate_scan_compliance,
)
from api.db_utils import tenant_transaction
from api.models import (
    Provider,
    Scan,
    Finding,
    Resource,
    ResourceTag,
    StatusChoices as FindingStatus,
    StateChoices,
    ComplianceOverview,
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
        resource_instance, created = Resource.objects.get_or_create(
            tenant_id=tenant_id,
            provider=provider_instance,
            uid=finding.resource_uid,
            defaults={
                "region": finding.region,
                "service": finding.service_name,
                "type": finding.resource_type,
            },
        )

        if not created:
            resource_instance.region = finding.region
            resource_instance.service = finding.service_name
            resource_instance.type = finding.resource_type
            resource_instance.save()
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
    generate_compliance = False
    check_status_by_region = {}
    exception = None
    unique_resources = set()
    start_time = time.time()

    with tenant_transaction(tenant_id):
        provider_instance = Provider.objects.get(pk=provider_id)
        scan_instance = Scan.objects.get(pk=scan_id)
        scan_instance.state = StateChoices.EXECUTING
        scan_instance.started_at = datetime.now(tz=timezone.utc)
        scan_instance.save()

        try:
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

            generate_compliance = (
                provider_instance.provider != Provider.ProviderChoices.GCP
            )
            prowler_scan = ProwlerScan(
                provider=prowler_provider, checks=checks_to_execute
            )

            resource_cache = {}
            tag_cache = {}
            last_status_cache = {}

            for progress, findings in prowler_scan.scan():
                for finding in findings:
                    # Process resource
                    resource_uid = finding.resource_uid
                    if resource_uid not in resource_cache:
                        # Get or create the resource
                        resource_instance, _ = Resource.objects.get_or_create(
                            tenant_id=tenant_id,
                            provider=provider_instance,
                            uid=resource_uid,
                            defaults={
                                "region": finding.region,
                                "service": finding.service_name,
                                "type": finding.resource_type,
                                "name": finding.resource_name or "",
                            },
                        )
                        resource_cache[resource_uid] = resource_instance
                    else:
                        resource_instance = resource_cache[resource_uid]

                    # Update resource fields if necessary
                    updated_fields = []
                    if resource_instance.region != finding.region:
                        resource_instance.region = finding.region
                        updated_fields.append("region")
                    if resource_instance.service != finding.service_name:
                        resource_instance.service = finding.service_name
                        updated_fields.append("service")
                    if resource_instance.type != finding.resource_type:
                        resource_instance.type = finding.resource_type
                        updated_fields.append("type")
                    if updated_fields:
                        resource_instance.save(update_fields=updated_fields)

                    # Update tags
                    tags = []
                    for key, value in finding.resource_tags.items():
                        tag_key = (key, value)
                        if tag_key not in tag_cache:
                            tag_instance, _ = ResourceTag.objects.get_or_create(
                                tenant_id=tenant_id, key=key, value=value
                            )
                            tag_cache[tag_key] = tag_instance
                        else:
                            tag_instance = tag_cache[tag_key]
                        tags.append(tag_instance)
                    resource_instance.upsert_or_delete_tags(tags=tags)

                    unique_resources.add(
                        (resource_instance.uid, resource_instance.region)
                    )

                    # Process finding
                    finding_uid = finding.uid
                    if finding_uid not in last_status_cache:
                        most_recent_finding = (
                            Finding.objects.filter(uid=finding_uid)
                            .order_by("-id")
                            .values("status")
                            .first()
                        )
                        last_status = (
                            most_recent_finding["status"]
                            if most_recent_finding
                            else None
                        )
                        last_status_cache[finding_uid] = last_status
                    else:
                        last_status = last_status_cache[finding_uid]

                    status = FindingStatus[finding.status]
                    delta = _create_finding_delta(last_status, status)

                    # Create the finding
                    finding_instance = Finding.objects.create(
                        tenant_id=tenant_id,
                        uid=finding_uid,
                        delta=delta,
                        check_metadata=finding.get_metadata(),
                        status=status,
                        status_extended=finding.status_extended,
                        severity=finding.severity,
                        impact=finding.severity,
                        raw_result=finding.raw,
                        check_id=finding.check_id,
                        scan=scan_instance,
                    )
                    finding_instance.add_resources([resource_instance])

                    # Update compliance data if applicable
                    if not generate_compliance or finding.status.value == "MUTED":
                        continue

                    region_dict = check_status_by_region.setdefault(finding.region, {})
                    current_status = region_dict.get(finding.check_id)
                    if current_status == "FAIL":
                        continue
                    region_dict[finding.check_id] = finding.status.value

                # Update scan progress
                scan_instance.progress = progress
                scan_instance.save()

            scan_instance.state = StateChoices.COMPLETED

        except Exception as e:
            logger.error(f"Error performing scan {scan_id}: {e}")
            exception = e
            scan_instance.state = StateChoices.FAILED

        finally:
            scan_instance.duration = time.time() - start_time
            scan_instance.completed_at = datetime.now(tz=timezone.utc)
            scan_instance.unique_resource_count = len(unique_resources)
            scan_instance.save()

    if generate_compliance:
        try:
            regions = prowler_provider.get_regions()
        except AttributeError:
            regions = set()

        compliance_template = PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE[
            provider_instance.provider
        ]
        compliance_overview_by_region = {
            region: deepcopy(compliance_template) for region in regions
        }

        for region, check_status in check_status_by_region.items():
            compliance_data = compliance_overview_by_region.setdefault(
                region, deepcopy(compliance_template)
            )
            for check_name, status in check_status.items():
                generate_scan_compliance(
                    compliance_data,
                    provider_instance.provider,
                    check_name,
                    status,
                )

        # Prepare compliance overview objects
        compliance_overview_objects = []
        for region, compliance_data in compliance_overview_by_region.items():
            for compliance_id, compliance in compliance_data.items():
                compliance_overview_objects.append(
                    ComplianceOverview(
                        tenant_id=tenant_id,
                        scan=scan_instance,
                        region=region,
                        compliance_id=compliance_id,
                        framework=compliance["framework"],
                        version=compliance["version"],
                        description=compliance["description"],
                        requirements=compliance["requirements"],
                        requirements_passed=compliance["requirements_status"]["passed"],
                        requirements_failed=compliance["requirements_status"]["failed"],
                        requirements_manual=compliance["requirements_status"]["manual"],
                        total_requirements=compliance["total_requirements"],
                    )
                )
        with tenant_transaction(tenant_id):
            ComplianceOverview.objects.bulk_create(compliance_overview_objects)

    if exception is not None:
        raise exception

    serializer = ScanTaskSerializer(instance=scan_instance)
    return serializer.data
