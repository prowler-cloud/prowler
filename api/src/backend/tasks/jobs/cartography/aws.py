import datetime
import traceback

from typing import Any, Iterable

import boto3
import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import aws as cartography_aws
from celery.utils.log import get_task_logger

from api.models import Provider as ProwlerAPIProvider
from prowler.providers.common.provider import Provider as ProwlerProvider

# TODO: Use the right logger
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger

logger = logging.getLogger(BackendLogger.API)


def start_aws_ingestion(
    neo4j_session: neo4j.Session,
    config: CartographyConfig,
    provider_api_provider: ProwlerAPIProvider,
    prowler_provider: ProwlerProvider,
) -> dict[str, dict[str, str]]:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.intel.aws.start_aws_ingestion`.
    """

    common_job_parameters = {
        "UPDATE_TAG": config.update_tag,
        "permission_relationships_file": config.permission_relationships_file,
        "aws_guardduty_severity_threshold": config.aws_guardduty_severity_threshold,
        "aws_cloudtrail_management_events_lookback_hours": config.aws_cloudtrail_management_events_lookback_hours,
    }

    # TODO: Check if there is a way to renew the session token if expired
    boto3_session = prowler_provider.session.current_session
    # Original: boto3_session = boto3.Session()

    aws_accounts_from_session = cartography_aws.organizations.get_aws_account_default(
        boto3_session
    )
    if not aws_accounts_from_session:
        logger.warning(
            "No valid AWS credentials could be found. No AWS accounts can be synced. Exiting AWS sync stage.",
        )
        return

    aws_account_id_from_session = list(aws_accounts_from_session.values())[0]
    if provider_api_provider.uid != aws_account_id_from_session:
        logger.warning(
            f"Provider {provider_api_provider.uid} does not match AWS account {aws_account_id_from_session}. "
            "Exiting AWS sync stage.",
        )
        return
    # Original: The account information was got from the session object, and multiple checks are done

    requested_syncs: list[str] = list(cartography_aws.RESOURCE_FUNCTIONS.keys())
    # Original: If `config.aws_requested_syncs` is set, they are parsed and validated

    regions = prowler_provider._enabled_regions
    # Original: regions = parse_and_validate_aws_regions(config.aws_regions)

    # TODO: Check if this is the right solution
    if boto3_session.region_name is None:
        global_region = prowler_provider.get_global_region()
        boto3_session._session.set_config_variable("region", global_region)
    # Original: There is no original for this, in Cartography the `AWS_DEFAULT_REGION`
    #           environment variable must be set or the boto3 client for some services will fail

    failed_account_id_exceptions = _sync_multiple_accounts(
        neo4j_session,
        boto3_session,
        provider_api_provider.uid,
        config.update_tag,
        common_job_parameters,
        config.aws_best_effort_mode,
        requested_syncs,
        regions=regions,
    )
    # Original: `_sync_multiple_accounts` returns a boolean indicating if the sync was successful or not

    if not failed_account_id_exceptions:
        cartography_aws._perform_aws_analysis(
            requested_syncs, neo4j_session, common_job_parameters
        )

    return failed_account_id_exceptions
    # Original: There is no return


def _sync_multiple_accounts(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.Session,
    provider_api_provider: ProwlerAPIProvider,
    sync_tag: int,
    common_job_parameters: dict[str, Any],
    aws_best_effort_mode: bool,
    aws_requested_syncs: list[str] = [],
    regions: list[str] | None = None,
) -> dict[str, dict[str, str]]:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.intel.aws._sync_multiple_accounts`.
    """

    profile_name = provider_api_provider.alias
    account_id = provider_api_provider.uid
    accounts = {
        profile_name: account_id,
    }
    # Origional: `accounts` was a function parameter

    logger.info("Syncing AWS accounts: %s", ", ".join(accounts.values()))
    cartography_aws.organizations.sync(
        neo4j_session, accounts, sync_tag, common_job_parameters
    )

    failed_account_id_exceptions = {}
    # Original: This variable is two lists: `failed_account_ids` and `exception_tracebacks`

    logger.info(
        "Syncing AWS account with ID '%s' using configured profile '%s'.",
        account_id,
        profile_name,
    )
    common_job_parameters["AWS_ID"] = account_id

    # TODO: Check if we can reuse the `boto3_session` from the function parameters or we need to create a new one
    #       per `profile_name`. Probably we don't need to create a new one as the `accounts` dict was created using
    #       `cartography_aws.organizations.get_aws_account_default` as `config.aws_sync_all_profiles` is None.
    # Original, for more than on account in `accounts`: `boto3_session = boto3.Session(profile_name=profile_name)`

    cartography_aws._autodiscover_accounts(
        neo4j_session,
        boto3_session,
        account_id,
        sync_tag,
        common_job_parameters,
    )

    failed_aws_requested_sync_exceptions = _sync_one_account(
        neo4j_session,
        boto3_session,
        account_id,
        sync_tag,
        common_job_parameters,
        regions=regions,
        aws_requested_syncs=aws_requested_syncs,  # Could be replaced later with per-account requested syncs
    )
    if failed_aws_requested_sync_exceptions:
        failed_account_id_exceptions[account_id] = failed_aws_requested_sync_exceptions
        failed_aws_requested_syncs = ",".join(failed_aws_requested_sync_exceptions.keys())
        logger.warning(
            f"Caught exceptions syncing account {account_id} in the functions {failed_aws_requested_syncs}",
        )

    # Original: As multiple AWS account could be hold in `boto3_session` there is a loop here to iterate over them

    # Original: `_sync_one_account` doesn't return anything, also this call is inside a try / except block that
    #           appends to two lists: `failed_account_ids` and `exception_tracebacks` if the `aws_best_effort_mode`
    #           config variable is set to `True`

    # Original: Here it logs and raises all the collected exceptions

    del common_job_parameters["AWS_ID"]

    # There may be orphan Principals which point outside of known AWS accounts. This job cleans
    # up those nodes after all AWS accounts have been synced.
    if not failed_account_id_exceptions:
        cartography_aws.run_cleanup_job(
            "aws_post_ingestion_principals_cleanup.json",
            neo4j_session,
            common_job_parameters,
        )

    return failed_account_id_exceptions
    # Original: It returns `True` or `False` depending on whether there were exceptions


def _sync_one_account(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.Session,
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: dict[str, Any],
    regions: list[str] | None = None,
    aws_requested_syncs: Iterable[str] = cartography_aws.RESOURCE_FUNCTIONS.keys(),
) -> dict[str, str]:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.intel.aws._sync_one_account`.
    """

    # Autodiscover the regions supported by the account unless the user has specified the regions to sync.
    if not regions:
        regions = cartography_aws._autodiscover_account_regions(boto3_session, current_aws_account_id)

    sync_args = cartography_aws._build_aws_sync_kwargs(
        neo4j_session,
        boto3_session,
        regions,
        current_aws_account_id,
        update_tag,
        common_job_parameters,
    )

    failed_aws_requested_sync_exceptions = {}
    # Original: This variable doesn't exist in the original code

    for func_name in aws_requested_syncs:
        if func_name in cartography_aws.RESOURCE_FUNCTIONS:
            logger.info(f"Syncing function {func_name} from AWS account {current_aws_account_id}")
            # Original: There is no log message here

            try:
                # Skip permission relationships and tags for now because they rely on data already being in the graph
                if func_name not in [
                    "permission_relationships",
                    "resourcegroupstaggingapi",
                ]:
                    cartography_aws.RESOURCE_FUNCTIONS[func_name](**sync_args)
                else:
                    continue

            except Exception as e:
                timestamp = datetime.datetime.now()
                exception_traceback = traceback.TracebackException.from_exception(e)
                traceback_string = "".join(exception_traceback.format())
                exception_message = f"{timestamp} - Exception for AWS sync function: {func_name}\n{traceback_string}"
                failed_aws_requested_sync_exceptions[func_name] = exception_message
                logger.warning(
                    f"Caught exception syncing function {func_name} from AWS account {current_aws_account_id}. We are "
                    f"continuing on to the next AWS sync function. All exceptions will be aggregated and re-logged at "
                    f"the end of the sync.",
                    exc_info=True,
                )
                continue
            # Original: The original code doesn't:
            #     1. Do a try / except block, if a AWS service sync fails the whole AWS account sync fails
            #     2. Collect exceptions for logging and returning them

        else:
            raise ValueError(
                f'AWS sync function "{func_name}" was specified but does not exist. Did you misspell it?',
            )

    # MAP IAM permissions
    if "permission_relationships" in aws_requested_syncs:
        cartography_aws.RESOURCE_FUNCTIONS["permission_relationships"](**sync_args)

    # AWS Tags - Must always be last.
    if "resourcegroupstaggingapi" in aws_requested_syncs:
        cartography_aws.RESOURCE_FUNCTIONS["resourcegroupstaggingapi"](**sync_args)

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
        group_id=current_aws_account_id,
        synced_type="AWSAccount",
        update_tag=update_tag,
        stat_handler=cartography_aws.stat_handler,
    )

    return failed_aws_requested_sync_exceptions
    # Original: There is no return
