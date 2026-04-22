# Portions of this file are based on code from the Cartography project
# (https://github.com/cartography-cncf/cartography), which is licensed under the Apache 2.0 License.

import time

from typing import Any

import aioboto3
import boto3
import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import aws as cartography_aws
from celery.utils.log import get_task_logger

from api.models import (
    AttackPathsScan as ProwlerAPIAttackPathsScan,
    Provider as ProwlerAPIProvider,
)
from prowler.providers.common.provider import Provider as ProwlerSDKProvider
from tasks.jobs.attack_paths import db_utils, utils

logger = get_task_logger(__name__)


def start_aws_ingestion(
    neo4j_session: neo4j.Session,
    cartography_config: CartographyConfig,
    prowler_api_provider: ProwlerAPIProvider,
    prowler_sdk_provider: ProwlerSDKProvider,
    attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> dict[str, dict[str, str]]:
    """
    Code based on Cartography, specifically on `cartography.intel.aws.__init__.py`.

    For the scan progress updates:
        - The caller of this function (`tasks.jobs.attack_paths.scan.run`) has set it to 2.
        - When the control returns to the caller, it will be set to 93.
    """

    # Initialize variables common to all jobs
    common_job_parameters = {
        "UPDATE_TAG": cartography_config.update_tag,
        "permission_relationships_file": cartography_config.permission_relationships_file,
        "aws_guardduty_severity_threshold": cartography_config.aws_guardduty_severity_threshold,
        "aws_cloudtrail_management_events_lookback_hours": cartography_config.aws_cloudtrail_management_events_lookback_hours,
        "experimental_aws_inspector_batch": cartography_config.experimental_aws_inspector_batch,
        "aws_tagging_api_cleanup_batch": cartography_config.aws_tagging_api_cleanup_batch,
    }

    boto3_session = get_boto3_session(prowler_api_provider, prowler_sdk_provider)
    regions: list[str] = list(prowler_sdk_provider._enabled_regions)
    requested_syncs = list(cartography_aws.RESOURCE_FUNCTIONS.keys())

    sync_args = cartography_aws._build_aws_sync_kwargs(
        neo4j_session,
        boto3_session,
        regions,
        prowler_api_provider.uid,
        cartography_config.update_tag,
        common_job_parameters,
    )

    # Starting with sync functions
    logger.info(f"Syncing organizations for AWS account {prowler_api_provider.uid}")
    cartography_aws.organizations.sync(
        neo4j_session,
        {prowler_api_provider.alias: prowler_api_provider.uid},
        cartography_config.update_tag,
        common_job_parameters,
    )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 3)

    # Adding an extra field
    common_job_parameters["AWS_ID"] = prowler_api_provider.uid

    cartography_aws._autodiscover_accounts(
        neo4j_session,
        boto3_session,
        prowler_api_provider.uid,
        cartography_config.update_tag,
        common_job_parameters,
    )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 4)

    failed_syncs = sync_aws_account(
        prowler_api_provider, requested_syncs, sync_args, attack_paths_scan
    )

    if "permission_relationships" in requested_syncs:
        logger.info(
            f"Syncing function permission_relationships for AWS account {prowler_api_provider.uid}"
        )
        t0 = time.perf_counter()
        cartography_aws.RESOURCE_FUNCTIONS["permission_relationships"](**sync_args)
        logger.info(
            f"Synced function permission_relationships for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
        )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 88)

    if "resourcegroupstaggingapi" in requested_syncs:
        logger.info(
            f"Syncing function resourcegroupstaggingapi for AWS account {prowler_api_provider.uid}"
        )
        t0 = time.perf_counter()
        cartography_aws.RESOURCE_FUNCTIONS["resourcegroupstaggingapi"](**sync_args)
        logger.info(
            f"Synced function resourcegroupstaggingapi for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
        )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 89)

    logger.info(
        f"Syncing ec2_iaminstanceprofile scoped analysis for AWS account {prowler_api_provider.uid}"
    )
    t0 = time.perf_counter()
    cartography_aws.run_scoped_analysis_job(
        "aws_ec2_iaminstanceprofile.json",
        neo4j_session,
        common_job_parameters,
    )
    logger.info(
        f"Synced ec2_iaminstanceprofile scoped analysis for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
    )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 90)

    logger.info(
        f"Syncing lambda_ecr analysis for AWS account {prowler_api_provider.uid}"
    )
    t0 = time.perf_counter()
    cartography_aws.run_analysis_job(
        "aws_lambda_ecr.json",
        neo4j_session,
        common_job_parameters,
    )
    logger.info(
        f"Synced lambda_ecr analysis for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
    )

    if all(
        s in requested_syncs
        for s in ["ecs", "ec2:load_balancer_v2", "ec2:load_balancer_v2:expose"]
    ):
        logger.info(
            f"Syncing lb_container_exposure scoped analysis for AWS account {prowler_api_provider.uid}"
        )
        t0 = time.perf_counter()
        cartography_aws.run_scoped_analysis_job(
            "aws_lb_container_exposure.json",
            neo4j_session,
            common_job_parameters,
        )
        logger.info(
            f"Synced lb_container_exposure scoped analysis for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
        )

    if all(s in requested_syncs for s in ["ec2:network_acls", "ec2:load_balancer_v2"]):
        logger.info(
            f"Syncing lb_nacl_direct scoped analysis for AWS account {prowler_api_provider.uid}"
        )
        t0 = time.perf_counter()
        cartography_aws.run_scoped_analysis_job(
            "aws_lb_nacl_direct.json",
            neo4j_session,
            common_job_parameters,
        )
        logger.info(
            f"Synced lb_nacl_direct scoped analysis for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
        )

    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 91)

    logger.info(f"Syncing metadata for AWS account {prowler_api_provider.uid}")
    t0 = time.perf_counter()
    cartography_aws.merge_module_sync_metadata(
        neo4j_session,
        group_type="AWSAccount",
        group_id=prowler_api_provider.uid,
        synced_type="AWSAccount",
        update_tag=cartography_config.update_tag,
        stat_handler=cartography_aws.stat_handler,
    )
    logger.info(
        f"Synced metadata for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
    )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 92)

    # Removing the added extra field
    del common_job_parameters["AWS_ID"]

    logger.info(f"Syncing analysis for AWS account {prowler_api_provider.uid}")
    t0 = time.perf_counter()
    cartography_aws._perform_aws_analysis(
        requested_syncs, neo4j_session, common_job_parameters
    )
    logger.info(
        f"Synced analysis for AWS account {prowler_api_provider.uid} in {time.perf_counter() - t0:.3f}s"
    )
    db_utils.update_attack_paths_scan_progress(attack_paths_scan, 93)

    return failed_syncs


def get_boto3_session(
    prowler_api_provider: ProwlerAPIProvider, prowler_sdk_provider: ProwlerSDKProvider
) -> boto3.Session:
    boto3_session = prowler_sdk_provider.session.current_session

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

    if boto3_session.region_name is None:
        global_region = prowler_sdk_provider.get_global_region()
        boto3_session._session.set_config_variable("region", global_region)

    return boto3_session


def get_aioboto3_session(boto3_session: boto3.Session) -> aioboto3.Session:
    return aioboto3.Session(botocore_session=boto3_session._session)


def sync_aws_account(
    prowler_api_provider: ProwlerAPIProvider,
    requested_syncs: list[str],
    sync_args: dict[str, Any],
    attack_paths_scan: ProwlerAPIAttackPathsScan,
) -> dict[str, str]:
    current_progress = 4  # `cartography_aws._autodiscover_accounts`
    max_progress = (
        87  # `cartography_aws.RESOURCE_FUNCTIONS["permission_relationships"]` - 1
    )
    n_steps = (
        len(requested_syncs) - 2
    )  # Excluding `permission_relationships` and `resourcegroupstaggingapi`
    progress_step = (max_progress - current_progress) / n_steps

    failed_syncs = {}

    for func_name in requested_syncs:
        if func_name in cartography_aws.RESOURCE_FUNCTIONS:
            logger.info(
                f"Syncing function {func_name} for AWS account {prowler_api_provider.uid}"
            )

            # Updating progress, not really the right place but good enough
            current_progress += progress_step
            db_utils.update_attack_paths_scan_progress(
                attack_paths_scan, int(current_progress)
            )

            try:
                func_t0 = time.perf_counter()

                # `ecr:image_layers` uses `aioboto3_session` instead of `boto3_session`
                if func_name == "ecr:image_layers":
                    cartography_aws.RESOURCE_FUNCTIONS[func_name](
                        neo4j_session=sync_args.get("neo4j_session"),
                        aioboto3_session=get_aioboto3_session(
                            sync_args.get("boto3_session")
                        ),
                        regions=sync_args.get("regions"),
                        current_aws_account_id=sync_args.get("current_aws_account_id"),
                        update_tag=sync_args.get("update_tag"),
                        common_job_parameters=sync_args.get("common_job_parameters"),
                    )

                # Skip permission relationships and tags for now because they rely on data already being in the graph
                elif func_name in [
                    "permission_relationships",
                    "resourcegroupstaggingapi",
                ]:
                    continue

                else:
                    cartography_aws.RESOURCE_FUNCTIONS[func_name](**sync_args)

                logger.info(
                    f"Synced function {func_name} for AWS account {prowler_api_provider.uid} in {time.perf_counter() - func_t0:.3f}s"
                )

            except Exception as e:
                logger.info(
                    f"Synced function {func_name} for AWS account {prowler_api_provider.uid} in {time.perf_counter() - func_t0:.3f}s (FAILED)"
                )

                exception_message = utils.stringify_exception(
                    e, f"Exception for AWS sync function: {func_name}"
                )
                failed_syncs[func_name] = exception_message

                logger.warning(
                    f"Caught exception syncing function {func_name} from AWS account {prowler_api_provider.uid}: {e}. "
                    "Continuing to the next AWS sync function.",
                    exc_info=True,
                )

                continue

        else:
            raise ValueError(
                f'AWS sync function "{func_name}" was specified but does not exist. Did you misspell it?'
            )

    return failed_syncs


def extract_short_uid(uid: str) -> str:
    """Return the short identifier from an AWS ARN or resource ID.

    Supported inputs end in one of:
      - `<type>/<id>`        (e.g. `instance/i-xxx`)
      - `<type>:<id>`        (e.g. `function:name`)
      - `<id>`               (e.g. `bucket-name` or `i-xxx`)

    If `uid` is already a short resource ID, it is returned unchanged.
    """
    return uid.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
