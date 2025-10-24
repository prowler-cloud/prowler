from datetime import datetime, timezone
from typing import Any

import neo4j

from api.db_utils import rls_transaction
from api.models import Provider, ResourceScanSummary
from cartography.intel import create_indexes as cartography_indexes
from cartography.intel.aws import organizations as cartography_organizations
from tasks.jobs.cartography.aws.analysis import perform_aws_analysis
from tasks.jobs.cartography.aws.ecs import sync_aws_ecs
from tasks.jobs.cartography.aws.iam import sync_aws_iam
from tasks.jobs.cartography.aws.s3 import sync_aws_s3


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
    regions = get_aws_provider_regions(tenant_id, scan_id)
    provider = get_aws_provider(tenant_id, provider_id)
    account_id = provider.uid
    provider_alias = provider.alias

    # Configuring Cartography job parameters
    update_tag = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    common_job_parameters = {"UPDATE_TAG": update_tag, "AWS_ID": account_id}

    # Creating Cartography indexes
    cartography_indexes.run(neo4j_session, None)

    # Syncing AWS Account
    accounts = {provider_alias: account_id}
    cartography_organizations.load_aws_accounts(neo4j_session, accounts, update_tag, common_job_parameters)

    # Syncing AWS resources
    result = {
        "iam": sync_aws_iam(tenant_id, provider_id, account_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),  # noqa: E501
        "s3": sync_aws_s3(tenant_id, provider_id, account_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),  # noqa: E501
        "ecs": sync_aws_ecs(tenant_id, provider_id, account_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),  # noqa: E501
    }

    # Running AWS analysis
    syncs = result.keys()
    perform_aws_analysis(account_id, syncs, regions, neo4j_session, update_tag, common_job_parameters)

    return result


def get_aws_provider(tenant_id: str, provider_id: str) -> str:
    """
    Getting AWS provider from Prowler DB.
    """

    with rls_transaction(tenant_id):
        provider = Provider.objects.get(pk=provider_id)

    return provider


def get_aws_provider_regions(tenant_id: str, scan_id: str) -> list[str]:
    """
    Getting AWS regions from Prowler DB for a provider in a specific scan.
    """

    with rls_transaction(tenant_id):
        regions_queryset = ResourceScanSummary.objects.filter(
            scan_id=scan_id,
        ).exclude(region="").values_list("region", flat=True).distinct().order_by("region")
    return list(regions_queryset)
