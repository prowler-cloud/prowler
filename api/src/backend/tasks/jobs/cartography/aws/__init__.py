from datetime import datetime, timezone
from typing import Any

import neo4j

from cartography.intel import aws as cartography_aws

from api.db_utils import rls_transaction
from api.models import Provider, ResourceScanSummary
from tasks.jobs.cartography.aws.s3 import sync_aws_s3
from tasks.jobs.cartography.aws.ecs import sync_aws_ecs
from tasks.jobs.cartography.aws.iam import sync_aws_iam


def sync_aws(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    neo4j_session: neo4j.Session,
) -> dict[str, Any]:
    """
    Sync AWS resources for a specific tenant and provider.
    """

    # Getting data from DB
    account_id = get_aws_provider_account_id(tenant_id, provider_id)
    regions = get_aws_provider_regions(tenant_id, scan_id)

    # Configuring Cartography job parameters
    update_tag = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    common_job_parameters = {"UPDATE_TAG": update_tag, "AWS_ID": account_id}

    return {
        "iam": sync_aws_iam(tenant_id, provider_id, account_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),  # noqa: E501
        "s3": sync_aws_s3(tenant_id, provider_id, account_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),  # noqa: E501
        "ecs": sync_aws_ecs(tenant_id, provider_id, account_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),  # noqa: E501
    }

def get_aws_provider_account_id(tenant_id: str, provider_id: str) -> str:
    """
    Getting AWS account ID from Prowler DB for a provider.
    """

    with rls_transaction(tenant_id):
        provider = Provider.objects.get(pk=provider_id)

    return provider.uid


def get_aws_provider_regions(tenant_id: str, scan_id: str) -> list[str]:
    """
    Getting AWS regions from Prowler DB for a provider in a specific scan.
    """

    with rls_transaction(tenant_id):
        regions_queryset = ResourceScanSummary.objects.filter(
            scan_id=scan_id,
        ).exclude(region="").values_list("region", flat=True).distinct().order_by("region")
    return list(regions_queryset)
