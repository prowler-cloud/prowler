import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import aws as cartography_aws
from celery.utils.log import get_task_logger

from api.models import Provider
from prowler.providers.common.provider import Provider as ProwlerProvider

logger = get_task_logger(__name__)


def start_aws_ingestion(
    neo4j_session: neo4j.Session,
    config: CartographyConfig,
    prowler_provider: ProwlerProvider,
) -> None:
    """
    Code based on `cartography.intel.aws.start_aws_ingestion`.
    """

    common_job_parameters = {
        "UPDATE_TAG": config.update_tag,
        "permission_relationships_file": config.permission_relationships_file,
        "aws_guardduty_severity_threshold": config.aws_guardduty_severity_threshold,
        "aws_cloudtrail_management_events_lookback_hours": config.aws_cloudtrail_management_events_lookback_hours,
    }

    boto3_session = prowler_provider.session.current_session

    if config.aws_sync_all_profiles:
        aws_accounts = cartography_aws.organizations.get_aws_accounts_from_botocore_config(
            boto3_session,
        )

    else:
        aws_accounts = cartography_aws.organizations.get_aws_account_default(boto3_session)

    if not aws_accounts:
        logger.warning(
            "No valid AWS credentials could be found. No AWS accounts can be synced. Exiting AWS sync stage.",
        )
        return

    if len(list(aws_accounts.values())) != len(set(aws_accounts.values())):
        logger.warning(
            (
                "There are duplicate AWS accounts in your AWS configuration. It is strongly recommended that you run "
                "cartography with an AWS configuration which has exactly one profile for each AWS account you want to "
                f"sync. Doing otherwise will result in undefined and untested behavior. Account list: {aws_accounts}"
            ),
        )

    requested_syncs: list[str] = list(cartography_aws.RESOURCE_FUNCTIONS.keys())
    if config.aws_requested_syncs:
        requested_syncs = cartography_aws.parse_and_validate_aws_requested_syncs(
            config.aws_requested_syncs,
        )

    if config.aws_regions:
        regions = cartography_aws.parse_and_validate_aws_regions(config.aws_regions)

    else:
        regions = None

    sync_successful = cartography_aws._sync_multiple_accounts(
        neo4j_session,
        aws_accounts,
        config.update_tag,
        common_job_parameters,
        config.aws_best_effort_mode,
        requested_syncs,
        regions=regions,
    )

    if sync_successful:
        cartography_aws._perform_aws_analysis(requested_syncs, neo4j_session, common_job_parameters)
