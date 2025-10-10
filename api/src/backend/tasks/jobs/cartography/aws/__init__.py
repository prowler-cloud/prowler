from datetime import datetime, timezone
from typing import Any

import neo4j

from tasks.jobs.cartography.aws.s3 import sync_aws_s3
from tasks.jobs.cartography.aws.ecs import sync_aws_ecs
from tasks.jobs.cartography.aws.iam import sync_aws_iam


def sync_aws(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
) -> dict[str, Any]:
    """
    Sync AWS resources for a specific tenant and provider.
    """

    regions = []  # TODO: Get `regions` from scan

    update_tag = int(datetime.now(tz=timezone.utc).timestamp() * 1000)  # TODO: Check if is calculated right
    common_job_parameters = {"UPDATE_TAG": update_tag}  # TODO: Add other stuff to `common_job_parameters`

    return {
        "s3": sync_aws_s3(tenant_id, provider_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),
        # "ecs": sync_aws_ecs(tenant_id, provider_id, scan_id, regions, neo4j_session, update_tag, common_job_parameters),
        # "iam": sync_aws_iam(tenant_id, provider_id, scan_id, neo4j_session, update_tag, common_job_parameters),
    }
