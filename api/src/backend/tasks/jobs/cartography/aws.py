# Portions of this file are based on code from the Cartography project
# (https://github.com/cartography-cncf/cartography), which is licensed under the Apache 2.0 License.

import datetime
import traceback

from typing import Any

import boto3
import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import aws as cartography_aws
from celery.utils.log import get_task_logger

from api.models import (
    CartographyScan as ProwlerAPICartographyScan,
    Provider as ProwlerAPIProvider,
)
from prowler.providers.common.provider import Provider as ProwlerSDKProvider
from tasks.jobs.cartography import db_utils

# TODO: Use the right logger
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger

logger = logging.getLogger(BackendLogger.API)


def start_aws_ingestion(
    neo4j_session: neo4j.Session,
    config: CartographyConfig,
    prowler_api_provider: ProwlerAPIProvider,
    prowler_provider: ProwlerSDKProvider,
    cartography_scan: ProwlerAPICartographyScan,
) -> dict[str, dict[str, str]]:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.intel.aws.__init__.py`.

    For the scan progress updates:
        - The caller of this function (`tasks.jobs.cartography.scan.run`) has set it to 2.
        - When the control returns to the caller, it will be set to 95.
    """

    # Initialize variables common to all jobs
    common_job_parameters = {
        "UPDATE_TAG": config.update_tag,
        "permission_relationships_file": config.permission_relationships_file,
        "aws_guardduty_severity_threshold": config.aws_guardduty_severity_threshold,
        "aws_cloudtrail_management_events_lookback_hours": config.aws_cloudtrail_management_events_lookback_hours,
    }

    # TODO: Check if there is a way to renew the session token if expired
    boto3_session = get_boto3_session(prowler_api_provider, prowler_provider)
    regions: list[str] = list(prowler_provider._enabled_regions)
    requested_syncs = list(cartography_aws.RESOURCE_FUNCTIONS.keys())

    sync_args = cartography_aws._build_aws_sync_kwargs(
        neo4j_session,
        boto3_session,
        regions,
        prowler_api_provider.uid,
        config.update_tag,
        common_job_parameters,
    )

    # Starting with sync functions
    cartography_aws.organizations.sync(
        neo4j_session,
        {prowler_api_provider.alias: prowler_api_provider.uid},
        config.update_tag,
        common_job_parameters,
    )
    db_utils.update_cartography_scan_progress(cartography_scan, 3)

    # Adding an extra field
    common_job_parameters["AWS_ID"] = prowler_api_provider.uid

    cartography_aws._autodiscover_accounts(
        neo4j_session,
        boto3_session,
        prowler_api_provider.uid,
        config.update_tag,
        common_job_parameters,
    )
    db_utils.update_cartography_scan_progress(cartography_scan, 4)

    failed_syncs = sync_aws_account(
        prowler_api_provider, requested_syncs, sync_args, cartography_scan
    )

    if "permission_relationships" in requested_syncs:
        cartography_aws.RESOURCE_FUNCTIONS["permission_relationships"](**sync_args)
    db_utils.update_cartography_scan_progress(cartography_scan, 88)

    if "resourcegroupstaggingapi" in requested_syncs:
        cartography_aws.RESOURCE_FUNCTIONS["resourcegroupstaggingapi"](**sync_args)
    db_utils.update_cartography_scan_progress(cartography_scan, 89)

    cartography_aws.run_scoped_analysis_job(
        "aws_ec2_iaminstanceprofile.json",
        neo4j_session,
        common_job_parameters,
    )
    db_utils.update_cartography_scan_progress(cartography_scan, 90)

    cartography_aws.run_analysis_job(
        "aws_lambda_ecr.json",
        neo4j_session,
        common_job_parameters,
    )
    db_utils.update_cartography_scan_progress(cartography_scan, 91)

    cartography_aws.merge_module_sync_metadata(
        neo4j_session,
        group_type="AWSAccount",
        group_id=prowler_api_provider.uid,
        synced_type="AWSAccount",
        update_tag=config.update_tag,
        stat_handler=cartography_aws.stat_handler,
    )
    db_utils.update_cartography_scan_progress(cartography_scan, 92)

    # Removing the added extra field
    del common_job_parameters["AWS_ID"]

    cartography_aws.run_cleanup_job(
        "aws_post_ingestion_principals_cleanup.json",
        neo4j_session,
        common_job_parameters,
    )
    db_utils.update_cartography_scan_progress(cartography_scan, 93)

    cartography_aws._perform_aws_analysis(
        requested_syncs, neo4j_session, common_job_parameters
    )
    db_utils.update_cartography_scan_progress(cartography_scan, 94)

    return failed_syncs


def get_boto3_session(
    prowler_api_provider: ProwlerAPIProvider, prowler_provider: ProwlerSDKProvider
) -> boto3.Session:
    boto3_session = prowler_provider.session.current_session

    aws_accounts_from_session = cartography_aws.organizations.get_aws_account_default(
        boto3_session
    )
    if not aws_accounts_from_session:
        raise Exception(
            "No valid AWS credentials could be found. No AWS accounts can be synced."
        )

    aws_account_id_from_session = list(aws_accounts_from_session.values())[0]
    if prowler_api_provider.uid != aws_account_id_from_session:
        raise Exception(
            f"Provider {prowler_api_provider.uid} doesn't match AWS account {aws_account_id_from_session}."
        )

    # TODO: Check if this is the right solution
    if boto3_session.region_name is None:
        global_region = prowler_provider.get_global_region()
        boto3_session._session.set_config_variable("region", global_region)

    return boto3_session


def sync_aws_account(
    prowler_api_provider: ProwlerAPIProvider,
    requested_syncs: list[str],
    sync_args: dict[str, Any],
    cartography_scan: ProwlerAPICartographyScan,
) -> dict[str, str]:
    current_progress = 4  # `cartography_aws._autodiscover_accounts`
    max_progress = (
        87  # `cartography_aws.RESOURCE_FUNCTIONS["permission_relationships"]` - 1
    )
    n_steps = len(requested_syncs)
    progress_step = (max_progress - current_progress) / n_steps

    failed_syncs = {}

    for func_name in requested_syncs:
        if func_name in cartography_aws.RESOURCE_FUNCTIONS:
            logger.info(
                f"Syncing function {func_name} from AWS account {prowler_api_provider.uid}"
            )

            # Updating progress, not really the right place but good enough
            current_progress += progress_step
            db_utils.update_cartography_scan_progress(
                cartography_scan, int(current_progress)
            )

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
                failed_syncs[func_name] = exception_message

                logger.warning(
                    f"Caught exception syncing function {func_name} from AWS account {prowler_api_provider.uid}. We "
                    "are continuing on to the next AWS sync function.",
                    exc_info=True,
                )

                continue

        else:
            raise ValueError(
                f'AWS sync function "{func_name}" was specified but does not exist. Did you misspell it?'
            )

    return failed_syncs
