import datetime
import traceback

from typing import Any

import boto3
import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import aws as cartography_aws
from celery.utils.log import get_task_logger

from prowler.providers.common.provider import Provider as ProwlerProvider

# TODO: Use the right logger
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger
logger = logging.getLogger(BackendLogger.API)


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
    # Original: boto3_session = boto3.Session()

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

    regions = prowler_provider._enabled_regions
    # Original: regions = parse_and_validate_aws_regions(config.aws_regions)

    # TODO: Check if this is the right solution
    if boto3_session.region_name is None:
        global_region = prowler_provider.get_global_region()
        boto3_session._session.set_config_variable("region", global_region)
    # Original: There is no original for this, in Cartography the `AWS_DEFAULT_REGION`
    #           environment variable must be set or the boto3 client for some services will fail

    sync_successful = _sync_multiple_accounts(
        neo4j_session,
        boto3_session,
        aws_accounts,
        config.update_tag,
        common_job_parameters,
        config.aws_best_effort_mode,
        requested_syncs,
        regions=regions,
    )

    if sync_successful:
        cartography_aws._perform_aws_analysis(requested_syncs, neo4j_session, common_job_parameters)


def _sync_multiple_accounts(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.Session,
    accounts: dict[str, str],
    sync_tag: int,
    common_job_parameters: dict[str, Any],
    aws_best_effort_mode: bool,
    aws_requested_syncs: list[str] = [],
    regions: list[str] | None = None,
) -> bool:
    """
    Code based on `cartography.intel.aws._sync_multiple_accounts`.
    """

    logger.info("Syncing AWS accounts: %s", ", ".join(accounts.values()))
    cartography_aws.organizations.sync(neo4j_session, accounts, sync_tag, common_job_parameters)

    failed_account_ids = []
    exception_tracebacks = []

    for profile_name, account_id in accounts.items():
        logger.info(
            "Syncing AWS account with ID '%s' using configured profile '%s'.",
            account_id,
            profile_name,
        )
        common_job_parameters["AWS_ID"] = account_id

        # TODO: Check if we can reuse the `boto3_session` from the function parameters or we need to create a new one
        #       per `profile_name`. Probably we don't need to create a new one as the `accounts` dict was created using
        #       `cartography_aws.organizations.get_aws_account_default` as `config.aws_sync_all_profiles` is None.
        # Original, for more than on account in `accounts`: boto3_session = boto3.Session(profile_name=profile_name)

        cartography_aws._autodiscover_accounts(
            neo4j_session,
            boto3_session,
            account_id,
            sync_tag,
            common_job_parameters,
        )

        try:
            cartography_aws._sync_one_account(
                neo4j_session,
                boto3_session,
                account_id,
                sync_tag,
                common_job_parameters,
                regions=regions,
                aws_requested_syncs=aws_requested_syncs,  # Could be replaced later with per-account requested syncs
            )
        except Exception as e:
            if aws_best_effort_mode:
                timestamp = datetime.datetime.now()
                failed_account_ids.append(account_id)
                exception_traceback = traceback.TracebackException.from_exception(e)
                traceback_string = "".join(exception_traceback.format())
                exception_tracebacks.append(
                    f"{timestamp} - Exception for account ID: {account_id}\n{traceback_string}",
                )
                logger.warning(
                    f"Caught exception syncing account {account_id}. aws-best-effort-mode is on so we are continuing "
                    f"on to the next AWS account. All exceptions will be aggregated and re-logged at the end of the "
                    f"sync.",
                    exc_info=True,
                )
                continue
            else:
                raise

    if failed_account_ids:
        logger.error(f"AWS sync failed for accounts {failed_account_ids}")
        raise Exception("\n".join(exception_tracebacks))

    del common_job_parameters["AWS_ID"]

    # There may be orphan Principals which point outside of known AWS accounts. This job cleans
    # up those nodes after all AWS accounts have been synced.
    if not failed_account_ids:
        cartography_aws.run_cleanup_job(
            "aws_post_ingestion_principals_cleanup.json",
            neo4j_session,
            common_job_parameters,
        )
        return True
    return False
