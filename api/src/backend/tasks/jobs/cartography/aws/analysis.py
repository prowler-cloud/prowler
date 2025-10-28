import neo4j

from typing import Any

from cartography.intel import aws as cartography_aws
# from cartography.intel.aws import permission_relationships as cartography_permission_relationships
# from cartography.intel.aws import resourcegroupstaggingapi as cartography_resourcegroupstaggingapi
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


def perform_aws_analysis(
    account_id: str,
    syncs: list[str],
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
    common_job_parameters: dict[str, Any],
):
    """
    Code based on `cartography.intel.aws._sync_multiple_accounts` and `cartography.intel.aws._sync_one_account`.
    # TODO: Check if we need to run `permission_relationships.sync`
    # TODO: Prowler DB doesn't save `resourcegroupstaggingapi`
    """

    # TODO: Check if we need to run `permission_relationships.sync` and with what `permission_relationships_file`
    # cartography_permission_relationships.sync(
    #     neo4j_session,
    #     None,  # `boto3_session` is not needed here
    #     regions,
    #     account_id,
    #     update_tag,
    #     common_job_parameters,
    # )

    # TODO: As `boto3_session` is needed for
    #       `boto3_session.client("resourcegroupstaggingapi", region_name=region)
    #       we can't call this function
    # cartography_resourcegroupstaggingapi.sync(
    #     neo4j_session
    #     None,  # `boto3_session` is REALLY needed here
    #     regions,
    #     account_id,
    #     update_tag,
    #     common_job_parameters,
    # )

    cartography_aws.run_scoped_analysis_job(
        "aws_ec2_iaminstanceprofile.json",
        neo4j_session,
        common_job_parameters,
    )

    cartography_aws.run_analysis_job(
        "aws_lambda_ecr.json",
        neo4j_session,
        common_job_parameters,
    )

    cartography_aws.merge_module_sync_metadata(
        neo4j_session,
        group_type="AWSAccount",
        group_id=account_id,
        synced_type="AWSAccount",
        update_tag=update_tag,
        stat_handler=cartography_aws.stat_handler,
    )

    cartography_aws.run_cleanup_job(
        "aws_post_ingestion_principals_cleanup.json",
        neo4j_session,
        common_job_parameters,
    )

    stringified_syncs = ",".join(syncs)
    requested_syncs = cartography_aws.parse_and_validate_aws_requested_syncs(stringified_syncs)
    cartography_aws._perform_aws_analysis(requested_syncs, neo4j_session, common_job_parameters)
