import json

from collections import defaultdict
from typing import Any

import neo4j

from cartography.intel.aws import iam as cartography_iam
from celery.utils.log import get_task_logger
from openai import containers

from api.db_utils import rls_transaction
from api.models import Resource, ResourceScanSummary

# TODO: Do the rigth logging setup
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger
logger = logging.getLogger(BackendLogger.API)


def sync_aws_iam(
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
    Entry point for syncing AWS IAM data into Cartography.
    """

    # Calling our version of cartography AWS IAM sync
    return _sync(
        tenant_id,
        provider_id,
        account_id,
        scan_id,
        regions,
        neo4j_session,
        update_tag,
        common_job_parameters,
    )


def _sync(
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
    Code based on `cartography.intel.aws.iam.sync`.
    """

    cartography_iam.sync_root_principal(
        neo4j_session,
        account_id,
        update_tag,
    )

    _sync_users(
        tenant_id,
        provider_id,
        account_id,
        scan_id,
        regions,
        neo4j_session,
        update_tag,
    )

    _sync_groups(
        tenant_id,
        provider_id,
        account_id,
        scan_id,
        regions,
        neo4j_session,
        update_tag,
    )

    _sync_roles(
        tenant_id,
        provider_id,
        account_id,
        scan_id,
        regions,
        neo4j_session,
        update_tag,
    )

    cartography_iam.sync_assumerole_relationships(
        neo4j_session,
        account_id,
        update_tag,
        common_job_parameters,
    )

    _sync_user_access_keys(
        tenant_id,
        provider_id,
        account_id,
        scan_id,
        regions,
        neo4j_session,
        update_tag,
        common_job_parameters,
    )

    cartography_iam.cleanup_iam(neo4j_session, common_job_parameters)

    cartography_iam.merge_module_sync_metadata(
        neo4j_session,
        group_type="AWSAccount",
        group_id=account_id,
        synced_type="AWSPrincipal",
        update_tag=update_tag,
        stat_handler=cartography_iam.stat_handler,
    )

    return {}

def _sync_users(
    tenant_id: str,
    provider_id: str,
    account_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
) -> None:

    user_data = _get_user_list_data(tenant_id, provider_id, scan_id, regions)
    transformed_user_data = cartography_iam.transform_users(user_data["Users"])

    cartography_iam.load_users(neo4j_session, transformed_user_data, account_id, update_tag)
    _sync_inline_policies(user_data["Users"], neo4j_session, update_tag, account_id)
    _sync_managed_policies(user_data["Users"], neo4j_session, update_tag, account_id)


def _get_user_list_data(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """
    Code based on `cartography.intel.aws.iam.get_user_list_data`.
    # TODO: There are missing fields to implement
    """

    users = []
    users_metadata = _get_users_metadata(tenant_id, provider_id, scan_id, regions)

    for user_metadata in users_metadata:
        user = {
            "Arn": user_metadata.get("arn"),
            "UserId": None,  # TODO
            "UserName": user_metadata.get("name"),
            "Path": None,  # TODO
            "CreateDate": user_metadata.get("inserted_at"),
            "PasswordLastUsed": user_metadata.get("password_last_used"),
            "InlinePolicies": user_metadata.get("inline_policies", []),
            "AttachedPolicies": user_metadata.get("attached_policies", []),
            "AccessKeyMetadata": user_metadata.get("access_keys_metadata", []),
        }
        users.append(user)

    return {"Users": users}


def _get_users_metadata(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> list[dict[str, Any]]:
    """
    Getting IAM users data from Prowler DB.
    """

    with rls_transaction(tenant_id):
        users_qs = Resource.objects.filter(
            provider_id=provider_id,
            id__in=ResourceScanSummary.objects.filter(
                scan_id=scan_id,
                service="iam",
                resource_type="AwsIamUser",
            ).values_list("resource_id", flat=True),
            region__in=regions,
        ).only("metadata", "inserted_at")

    users_metadata = []
    for user in users_qs:
        user_metadata = json.loads(user.metadata)
        user_metadata["inserted_at"] = user.inserted_at
        users_metadata.append(user_metadata)

    return users_metadata


def _sync_inline_policies(
    resource_data: list[dict[str, Any]],
    neo4j_session: neo4j.Session,
    update_tag: int,
    account_id: str,
) -> None:
    """
    Code based on `cartography.intel.aws.iam.sync_[user|group|role|]_inline_policies`.
    """

    inline_policy_data = _get_inline_resource_policy_data(resource_data)
    transformed_inline_policy_data = cartography_iam.transform_policy_data(
        inline_policy_data,
        cartography_iam.PolicyType.inline.value,
    )

    cartography_iam.load_policy_data(
        neo4j_session,
        transformed_inline_policy_data,
        update_tag,
        account_id,
    )


def _get_inline_resource_policy_data(resource_data: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Code based on `cartography.intel.aws.iam.get_[user|group|role]_policy_data`.
    # TODO: It looks like Prowler does not store AWS IAM [User|Group|Role] policies document statement
    """

    inline_policies = {}

    for resource in resource_data:
        inline_policies[resource.get("Arn")] = {
            policy_name: None  # TODO: The policy document statement is missing
            for policy_name in resource.get("InlinePolicies", [])
        }

    return inline_policies


def _sync_managed_policies(
    resource_data: list[dict[str, Any]],
    neo4j_session: neo4j.Session,
    update_tag: int,
    account_id: str,
) -> None:
    """
    Code based on `cartography.intel.aws.iam.sync_[user|group|role|]_managed_policies`.
    """

    managed_policy_data = _get_resource_managed_policy_data(resource_data)
    transformed_policy_data = cartography_iam.transform_policy_data(
        managed_policy_data,
        cartography_iam.PolicyType.managed.value,
    )

    cartography_iam.load_policy_data(
        neo4j_session,
        transformed_policy_data,
        update_tag,
        account_id,
    )


def _get_resource_managed_policy_data(resource_data: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Code based on `cartography.intel.aws.iam.get_[user|group|role]_managed_policy_data`.
    # TODO: It looks like Prowler does not store AWS IAM [User|Group|Role] attached policy default
    #       version document statement
    """

    attached_policies = {}

    for resource in resource_data:
        attached_policies[resource.get("Arn")] = {
            policy.get("PolicyArn"): None  # TODO: The policy default version document statement is missing
            for policy in resource.get("AttachedPolicies", [])
        }

    return attached_policies


def _sync_groups(
    tenant_id: str,
    provider_id: str,
    account_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
):
    """
    Code based on `cartography.intel.aws.iam.sync_groups`.
    """

    group_data = _get_group_list_data(tenant_id, provider_id, scan_id, regions)
    group_memberships = _get_group_memberships(group_data["Groups"])
    transformed_group_data = cartography_iam.transform_groups(group_data["Groups"], group_memberships)

    cartography_iam.load_groups(neo4j_session, transformed_group_data, account_id, update_tag)

    _sync_inline_policies(group_data["Groups"], neo4j_session, update_tag, account_id)

    _sync_managed_policies(group_data["Groups"], neo4j_session, update_tag, account_id)


def _get_group_list_data(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """
    Code based on `cartography.intel.aws.iam.get_group_list_data`.
    # TODO: There are missing fields to implement
    """

    groups = []
    groups_metadata = _get_groups_metadata(tenant_id, provider_id, scan_id, regions)

    for group_metadata in groups_metadata:
        group = {
            "Arn": group_metadata.get("arn"),
            "GroupId": None,  # TODO
            "GroupName": group_metadata.get("name"),
            "Path": None,  # TODO
            "CreateDate": group_metadata.get("inserted_at"),
            "Users": group_metadata.get("users", []),
            "InlinePolicies": group_metadata.get("inline_policies", []),
            "AttachedPolicies": group_metadata.get("attached_policies", []),
        }
        groups.append(group)

    return {"Groups": groups}


def _get_groups_metadata(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> list[dict[str, Any]]:
    """
    Getting IAM groups data from Prowler DB.
    """

    with rls_transaction(tenant_id):
        groups_qs = Resource.objects.filter(
            provider_id=provider_id,
            id__in=ResourceScanSummary.objects.filter(
                scan_id=scan_id,
                service="iam",
                resource_type="AwsIamGroup",
            ).values_list("resource_id", flat=True),
            region__in=regions,
        ).only("metadata", "inserted_at")

    groups_metadata = []
    for group in groups_qs:
        group_metadata = json.loads(group.metadata)
        group_metadata["inserted_at"] = group.inserted_at
        groups_metadata.append(group_metadata)

    return groups_metadata


def _get_group_memberships(group_data: list[dict[str, Any]]) -> dict[str, list[str]]:
    """
    Code based on `cartography.intel.aws.iam.get_group_memberships`.
    """

    group_memberships = {}

    for group in group_data:
        group_memberships[group.get("Arn")] = [
            user.get("arn") for user in group.get("Users", [])
        ]

    return group_memberships


def _sync_roles(
    tenant_id: str,
    provider_id: str,
    account_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
):
    """
    Code based on `cartography.intel.aws.iam.sync_roles`.
    """

    roles_data = _get_role_list_data(tenant_id, provider_id, scan_id, regions)

    cartography_iam.sync_role_assumptions(neo4j_session, roles_data, account_id, update_tag)

    _sync_inline_policies(roles_data["Roles"], neo4j_session, update_tag, account_id)

    _sync_managed_policies(roles_data["Roles"], neo4j_session, update_tag, account_id)


def _get_role_list_data(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """
    Code based on `cartography.intel.aws.iam.get_role_list_data`.
    # TODO: There are missing fields to implement
    """

    roles = []
    roles_metadata = _get_roles_metadata(tenant_id, provider_id, scan_id, regions)

    for role_metadata in roles_metadata:
        role = {
            "Arn": role_metadata.get("arn"),
            "RoleId": None,  # TODO
            "RoleName": role_metadata.get("name"),
            "Path": None,  # TODO
            "CreateDate": role_metadata.get("inserted_at"),
            "AssumeRolePolicyDocument": role_metadata.get("assume_role_policy", {}),
            "Tags": role_metadata.get("tags", []),
            "InlinePolicies": role_metadata.get("inline_policies", []),
            "AttachedPolicies": role_metadata.get("attached_policies", []),
        }
        roles.append(role)

    return {"Roles": roles}


def _get_roles_metadata(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
    regions: list[str],
) -> list[dict[str, Any]]:
    """
    Getting IAM roles data from Prowler DB.
    """

    with rls_transaction(tenant_id):
        roles_qs = Resource.objects.filter(
            provider_id=provider_id,
            id__in=ResourceScanSummary.objects.filter(
                scan_id=scan_id,
                service="iam",
                resource_type="AwsIamRole",
            ).values_list("resource_id", flat=True),
            region__in=regions,
        ).only("metadata", "inserted_at")

    roles_metadata = []
    for role in roles_qs:
        role_metadata = json.loads(role.metadata)
        role_metadata["inserted_at"] = role.inserted_at
        roles_metadata.append(role_metadata)

    return roles_metadata


def _sync_user_access_keys(
    tenant_id: str,
    provider_id: str,
    account_id: str,
    scan_id: str,
    regions: list[str],
    neo4j_session: neo4j.Session,
    update_tag: int,
    common_job_parameters: dict[str, Any],
):
    """
    Code based on `cartography.intel.aws.iam.sync_user_access_keys`.
    """

    user_data = _get_user_list_data(tenant_id, provider_id, scan_id, regions)
    user_access_keys = _pretransform_access_keys(user_data["Users"])
    access_key_data = cartography_iam.transform_access_keys(user_access_keys)
    cartography_iam.load_access_keys(
        neo4j_session, access_key_data, update_tag, account_id
    )
    cartography_iam.GraphJob.from_node_schema(
        cartography_iam.AccountAccessKeySchema(),
        common_job_parameters,
    ).run(
        neo4j_session,
    )


def _pretransform_access_keys(users: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Code based on `cartography.intel.aws.iam.get_user_access_keys_data`.
    # TODO: Some AWS IAM Access Key `last_used_info` data is missing from Prowler DB
    """

    user_access_keys = {}

    for user in users:
        user_access_keys[user.get("Arn")] = user.get("AccessKeyMetadata", [])

    return user_access_keys
