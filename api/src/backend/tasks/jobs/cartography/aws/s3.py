import json

from typing import Any

import neo4j

from cartography.intel.aws import s3 as cartography_s3
from celery.utils.log import get_task_logger

from api.db_utils import rls_transaction
from api.models import Resource, ResourceScanSummary

logger = get_task_logger(__name__)


def sync_aws_s3(
    tenant_id: str,
    provider_id: str,
    account_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
    common_job_parameters: dict[str, Any],
) -> dict[str, Any]:
    """
    Entry point for syncing AWS S3 data into Cartography.
    """

    # Getting scan data from Prowler DB
    buckets_metadata = _get_s3_buckets_metadata(tenant_id, provider_id, scan_id, regions)

    # Calling our version of cartography AWS S3 sync
    return _sync(
        neo4j_session,
        account_id,
        buckets_metadata,
        update_tag,
        common_job_parameters,
    )


def _get_s3_buckets_metadata(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> list(dict[str, Any]):
    """
    Getting S3 buckets metadata from Prowler DB.
    """

    with rls_transaction(tenant_id):
        buckets_qs = Resource.objects.filter(
            provider_id=provider_id,
            id__in=ResourceScanSummary.objects.filter(
                scan_id=scan_id,
                service="s3",
                resource_type="AwsS3Bucket",
            ).values_list("resource_id", flat=True),
            region__in=regions,
        ).only("metadata", "inserted_at")

    buckets_metadata = []
    for bucket in buckets_qs:
        bucket_metadata = json.loads(bucket.metadata)
        bucket_metadata["inserted_at"] = bucket.inserted_at

        if bucket_metadata.get("name"):
            buckets_metadata.append(bucket_metadata)

    return buckets_metadata


def _sync(
    neo4j_session: neo4j.Session,
    account_id: str,
    buckets_metadata: list[dict[str, Any]],
    update_tag: int,
    common_job_parameters: dict[str, Any],
) -> dict[str, Any]:
    """
    Code based on `cartography.intel.aws.s3.sync`.
    """

    bucket_list = _get_s3_bucket_list(buckets_metadata)
    cartography_s3.load_s3_buckets(neo4j_session, bucket_list, account_id, update_tag)
    cartography_s3.cleanup_s3_buckets(neo4j_session, common_job_parameters)

    _get_and_load_s3_bucket_details(neo4j_session, buckets_metadata, account_id, update_tag)

    cartography_s3.cleanup_s3_bucket_acl_and_policy(neo4j_session, common_job_parameters)

    bucket_notifications = _sync_s3_notifications(neo4j_session, buckets_metadata, update_tag)

    cartography_s3.merge_module_sync_metadata(
        neo4j_session,
        group_type="AWSAccount",
        group_id=account_id,
        synced_type="S3Bucket",
        update_tag=update_tag,
        stat_handler=cartography_s3.stat_handler,
    )

    return {
        "buckets": len(buckets_metadata),
        "notifications": len(bucket_notifications),
    }


def _get_s3_bucket_list(buckets_metadata: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Code based on `cartography.intel.aws.s3.get_s3_bucket_list`.
    """

    bucket_list = []
    for bucket_metadata in buckets_metadata:
        bucket_list.append({
            "Name": bucket_metadata.get("name"),
            "Region": bucket_metadata.get("region"),
            "CreationDate": bucket_metadata.get("inserted_at"),
        })

    return {"Buckets": bucket_list}


def _get_and_load_s3_bucket_details(
    neo4j_session: neo4j.Session,
    buckets_metadata: list[dict[str, Any]],
    account_id: str,
    update_tag: int,
) -> None:
    """
    Code based on `cartography.intel.aws.s3.get_s3_bucket_details` and `cartography.intel.aws.s3.load_s3_details`.
    """

    acls: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []
    statements: list[dict[str, Any]] = []
    encryption_configs: list[dict[str, Any]] = []
    versioning_configs: list[dict[str, Any]] = []
    public_access_block_configs: list[dict[str, Any]] = []
    bucket_ownership_controls_configs: list[dict[str, Any]] = []
    bucket_logging_configs: list[dict[str, Any]] = []

    for bucket_metadata in buckets_metadata:
        parsed_acls = _parse_s3_bucket_acl(bucket_metadata, account_id)
        if parsed_acls is not None:
            acls.extend(parsed_acls)

        parsed_policy = _parse_s3_bucket_policy(bucket_metadata)
        if parsed_policy is not None:
            policies.append(parsed_policy)

        parsed_statements = _parse_s3_bucket_policy_statements(bucket_metadata)
        if parsed_statements is not None:
            statements.extend(parsed_statements)

        parsed_encryption = _parse_s3_bucket_encryption(bucket_metadata)
        if parsed_encryption is not None:
            encryption_configs.append(parsed_encryption)

        parsed_versioning = _parse_s3_bucket_versioning(bucket_metadata)
        versioning_configs.append(parsed_versioning)

        parsed_public_access_block = _parse_s3_bucket_public_access_block(bucket_metadata)
        public_access_block_configs.append(parsed_public_access_block)

        parsed_bucket_ownership_controls = _parse_s3_bucket_ownership_controls(bucket_metadata)
        bucket_ownership_controls_configs.append(parsed_bucket_ownership_controls)

        parsed_bucket_logging = _parse_s3_bucket_bucket_logging(bucket_metadata)
        bucket_logging_configs.append(parsed_bucket_logging)

    cartography_s3.run_cleanup_job(
        "aws_s3_details.json",
        neo4j_session,
        {"UPDATE_TAG": update_tag, "AWS_ID": account_id},
    )

    cartography_s3._load_s3_acls(neo4j_session, acls, account_id, update_tag)
    cartography_s3._load_s3_policies(neo4j_session, policies, update_tag)
    cartography_s3._load_s3_policy_statements(neo4j_session, statements, update_tag)
    cartography_s3._load_s3_encryption(neo4j_session, encryption_configs, update_tag)
    cartography_s3._load_s3_versioning(neo4j_session, versioning_configs, update_tag)
    cartography_s3._load_s3_public_access_block(neo4j_session, public_access_block_configs, update_tag)
    cartography_s3._load_bucket_ownership_controls(neo4j_session, bucket_ownership_controls_configs, update_tag)
    cartography_s3._load_bucket_logging(neo4j_session, bucket_logging_configs, update_tag)

    cartography_s3._set_default_values(neo4j_session, account_id)


def _parse_s3_bucket_acl(bucket_metadata: dict[str, Any], account_id: str) -> dict[str, Any] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_acl`.
    # TODO: Key `EmailAddress` is not implemented yet
    """

    if not bucket_metadata.get("acl_grantees"):
        return None

    acl = {
        "Grants": [],
        "Owner": {
            "ID": bucket_metadata.get("owner_id"),
            "DisplayName": None,
        }
    }

    for grantee in bucket_metadata.get("acl_grantees"):
        acl["Grants"].append({
            "Grantee": {
                "DisplayName": grantee.get("display_name"),
                # "EmailAddress"  # TODO: Grantee.EmailAddress
                "ID": grantee.get("ID"),
                "Type": grantee.get("type"),
                "URI": grantee.get("URI"),
            },
            "Permission": grantee.get("permission"),
        })

    return cartography_s3.parse_acl(acl, bucket_metadata.get("name"), account_id)


def _parse_s3_bucket_policy(bucket_metadata: dict[str, Any]) -> dict[str, Any] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_policy`.
    """
    if not bucket_metadata.get("policy"):
        return None

    policy = {
        "Policy": json.dumps(bucket_metadata.get("policy")),
    }
    return cartography_s3.parse_policy(bucket_metadata.get("name"), policy)


def _parse_s3_bucket_policy_statements(bucket_metadata: dict[str, Any]) -> list[dict[str, Any]] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_policy_statements`.
    """
    if not bucket_metadata.get("policy"):
        return None

    policy = {
        "Policy": json.dumps(bucket_metadata.get("policy")),
    }
    return cartography_s3.parse_policy_statements(bucket_metadata.get("name"), policy)


def _parse_s3_bucket_encryption(bucket_metadata: dict[str, Any]) -> dict[str, Any] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_encryption`.
    # TODO: Keys `encryption_key_id` and `bucket_key_enabled` are not implemented yet
    """

    if not bucket_metadata.get("encryption"):
        return None

    return {
        "bucket": bucket_metadata.get("name"),
        "default_encryption": True,
        "encryption_algorithm": bucket_metadata.get("encryption"),  # ServerSideEncryptionConfiguration.Rules[-1].ApplyServerSideEncryptionByDefault.SSEAlgorithm  # noqa: E501
        # "encryption_key_id"  # TODO:  ServerSideEncryptionConfiguration.Rules[-1].ApplyServerSideEncryptionByDefault.KMSMasterKeyID  # noqa: E501
        # "bucket_key_enabled"  # TODO: ServerSideEncryptionConfiguration.Rules[-1].BucketKeyEnabled
    }


def _parse_s3_bucket_versioning(bucket_metadata: dict[str, Any]) -> dict[str, Any] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_versioning`.
    """

    return {
        "bucket": bucket_metadata.get("name"),
        "status": "Enabled" if bucket_metadata.get("versioning") else "Suspended",
        "mfa_delete": "Enabled" if bucket_metadata.get("mfa_delete") else "Disabled",
    }


def _parse_s3_bucket_public_access_block(bucket_metadata: dict[str, Any]) -> dict[str, Any] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_public_access_block`.
    """

    return {
        "bucket": bucket_metadata.get("name"),
        **bucket_metadata.get("public_access_block"),
    }


def _parse_s3_bucket_ownership_controls(bucket_metadata: dict[str, Any]) -> dict[str, Any] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_bucket_ownership_controls`.
    """

    return {
        "bucket": bucket_metadata.get("name"),
        "object_ownership": bucket_metadata.get("ownership"),
    }


def _parse_s3_bucket_bucket_logging(bucket_metadata: dict[str, Any]) -> dict[str, Any] | None:
    """
    Code based on `cartography.intel.aws.s3.parse_bucket_logging`.
    """

    return {
        "bucket": bucket_metadata.get("name"),
        "logging_enabled": bucket_metadata.get("logging"),
        "target_bucket": bucket_metadata.get("logging_target_bucket"),
    }


def _parse_s3_notifications(buckets_metadata: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Code based on `cartography.intel.aws.s3.parse_notification_configuration`.
    """

    notifications: list[dict[str, Any]] = []
    for bucket_metadata in buckets_metadata:
        for bucket_topic_configuration in bucket_metadata.get("notification_config", {}).get("TopicConfigurations", []):
            notifications.append({
                "bucket": bucket_metadata.get("name"),
                "TopicArn": bucket_topic_configuration.get("TopicArn"),
            })

    return notifications


def _sync_s3_notifications(
        neo4j_session: neo4j.Session,
        buckets_metadata: list[dict[str, Any]],
        update_tag: int,
) -> list[dict[str, Any]]:
    """
    Prowler version of Cartography's `cartography.intel.aws.s3._sync_s3_notifications`
    as we already have the needed information for building the S3 bucket notifications data.
    """

    bucket_notifications = _parse_s3_notifications(buckets_metadata)
    cartography_s3._load_s3_notifications(neo4j_session, bucket_notifications, update_tag)
    return bucket_notifications
