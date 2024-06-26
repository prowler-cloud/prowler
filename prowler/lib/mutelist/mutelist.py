import re
from typing import Any

import yaml

from prowler.lib.logger import logger
from prowler.lib.mutelist.models import mutelist_schema
from prowler.lib.outputs.utils import unroll_tags


def get_mutelist_file_from_local_file(mutelist_path: str):
    try:
        with open(mutelist_path) as f:
            mutelist = yaml.safe_load(f)["Mutelist"]
            return mutelist
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return {}


def validate_mutelist(mutelist: dict) -> dict:
    try:
        mutelist = mutelist_schema.validate(mutelist)
        return mutelist
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- Mutelist YAML is malformed - {error}[{error.__traceback__.tb_lineno}]"
        )
        return {}


def mutelist_findings(
    global_provider: Any,
    check_findings: list[Any],
) -> list[Any]:
    # Check if finding is muted
    for finding in check_findings:
        # TODO: Move this mapping to the execute_check function and pass that output to the mutelist and the report
        if global_provider.type == "aws":
            finding.muted = is_muted(
                global_provider.mutelist,
                global_provider.identity.account,
                finding.check_metadata.CheckID,
                finding.region,
                finding.resource_id,
                unroll_tags(finding.resource_tags),
            )
        elif global_provider.type == "azure":
            finding.muted = is_muted(
                global_provider.mutelist,
                finding.subscription,
                finding.check_metadata.CheckID,
                # TODO: add region to the findings when we add Azure Locations
                # finding.region,
                "",
                finding.resource_name,
                unroll_tags(finding.resource_tags),
            )
        elif global_provider.type == "gcp":
            finding.muted = is_muted(
                global_provider.mutelist,
                finding.project_id,
                finding.check_metadata.CheckID,
                finding.location,
                finding.resource_name,
                unroll_tags(finding.resource_tags),
            )
        elif global_provider.type == "kubernetes":
            finding.muted = is_muted(
                global_provider.mutelist,
                global_provider.identity.cluster,
                finding.check_metadata.CheckID,
                finding.namespace,
                finding.resource_name,
                unroll_tags(finding.resource_tags),
            )
    return check_findings


def is_muted(
    mutelist: dict,
    audited_account: str,
    check: str,
    finding_region: str,
    finding_resource: str,
    finding_tags,
) -> bool:
    """
    Check if the provided finding is muted for the audited account, check, region, resource and tags.

    Args:
        mutelist (dict): Dictionary containing information about muted checks for different accounts.
        audited_account (str): The account being audited.
        check (str): The check to be evaluated for muting.
        finding_region (str): The region where the finding occurred.
        finding_resource (str): The resource related to the finding.
        finding_tags: The tags associated with the finding.

    Returns:
        bool: True if the finding is muted for the audited account, check, region, resource and tags., otherwise False.
    """
    try:
        # By default is not muted
        is_finding_muted = False

        # We always check all the accounts present in the mutelist
        # if one mutes the finding we set the finding as muted
        for account in mutelist["Accounts"]:
            if account == audited_account or account == "*":
                if is_muted_in_check(
                    mutelist["Accounts"][account]["Checks"],
                    audited_account,
                    check,
                    finding_region,
                    finding_resource,
                    finding_tags,
                ):
                    is_finding_muted = True
                    break

        return is_finding_muted
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_muted_in_check(
    muted_checks,
    audited_account,
    check,
    finding_region,
    finding_resource,
    finding_tags,
) -> bool:
    """
    Check if the provided check is muted.

    Args:
        muted_checks (dict): Dictionary containing information about muted checks.
        audited_account (str): The account to be audited.
        check (str): The check to be evaluated for muting.
        finding_region (str): The region where the finding occurred.
        finding_resource (str): The resource related to the finding.
        finding_tags (str): The tags associated with the finding.

    Returns:
        bool: True if the check is muted, otherwise False.
    """
    try:
        # Default value is not muted
        is_check_muted = False

        for muted_check, muted_check_info in muted_checks.items():
            # map lambda to awslambda
            muted_check = re.sub("^lambda", "awslambda", muted_check)

            check_match = (
                "*" == muted_check
                or check == muted_check
                or re.search(muted_check, check)
            )
            # Check if the finding is excepted
            exceptions = muted_check_info.get("Exceptions")
            if (
                is_excepted(
                    exceptions,
                    audited_account,
                    finding_region,
                    finding_resource,
                    finding_tags,
                )
                and check_match
            ):
                # Break loop and return default value since is excepted
                break

            muted_regions = muted_check_info.get("Regions")
            muted_resources = muted_check_info.get("Resources")
            muted_tags = muted_check_info.get("Tags", "*")
            # We need to set the muted_tags if None, "" or [], so the falsy helps
            if not muted_tags:
                muted_tags = "*"
            # If there is a *, it affects to all checks
            if check_match:
                muted_in_check = True
                muted_in_region = is_muted_in_region(muted_regions, finding_region)
                muted_in_resource = is_muted_in_resource(
                    muted_resources, finding_resource
                )
                muted_in_tags = is_muted_in_tags(muted_tags, finding_tags)

                # For a finding to be muted requires the following set to True:
                # - muted_in_check -> True
                # - muted_in_region -> True
                # - muted_in_tags -> True
                # - muted_in_resource -> True
                # - excepted -> False

                if (
                    muted_in_check
                    and muted_in_region
                    and muted_in_tags
                    and muted_in_resource
                ):
                    is_check_muted = True

        return is_check_muted
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_muted_in_region(
    mutelist_regions,
    finding_region,
) -> bool:
    """
    Check if the finding_region is present in the mutelist_regions.

    Args:
        mutelist_regions (list): List of regions in the mute list.
        finding_region (str): Region to check if it is muted.

    Returns:
        bool: True if the finding_region is muted in any of the mutelist_regions, otherwise False.
    """
    try:
        return __is_item_matched__(mutelist_regions, finding_region)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_muted_in_tags(muted_tags, finding_tags) -> bool:
    """
    Check if any of the muted tags are present in the finding tags.

    Args:
        muted_tags (list): List of muted tags to be checked.
        finding_tags (str): String containing tags to search for muted tags.

    Returns:
        bool: True if any of the muted tags are present in the finding tags, otherwise False.
    """
    try:
        return __is_item_matched__(muted_tags, finding_tags)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_muted_in_resource(muted_resources, finding_resource) -> bool:
    """
    Check if any of the muted_resources are present in the finding_resource.

    Args:
        muted_resources (list): List of muted resources to be checked.
        finding_resource (str): Resource to search for muted resources.

    Returns:
        bool: True if any of the muted_resources are present in the finding_resource, otherwise False.
    """
    try:
        return __is_item_matched__(muted_resources, finding_resource)

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_excepted(
    exceptions,
    audited_account,
    finding_region,
    finding_resource,
    finding_tags,
) -> bool:
    """
    Check if the provided account, region, resource, and tags are excepted based on the exceptions dictionary.

    Args:
        exceptions (dict): Dictionary containing exceptions for different attributes like Accounts, Regions, Resources, and Tags.
        audited_account (str): The account to be audited.
        finding_region (str): The region where the finding occurred.
        finding_resource (str): The resource related to the finding.
        finding_tags (str): The tags associated with the finding.

    Returns:
        bool: True if the account, region, resource, and tags are excepted based on the exceptions, otherwise False.
    """
    try:
        excepted = False
        is_account_excepted = False
        is_region_excepted = False
        is_resource_excepted = False
        is_tag_excepted = False
        if exceptions:
            excepted_accounts = exceptions.get("Accounts", [])
            is_account_excepted = __is_item_matched__(
                excepted_accounts, audited_account
            )

            excepted_regions = exceptions.get("Regions", [])
            is_region_excepted = __is_item_matched__(excepted_regions, finding_region)

            excepted_resources = exceptions.get("Resources", [])
            is_resource_excepted = __is_item_matched__(
                excepted_resources, finding_resource
            )

            excepted_tags = exceptions.get("Tags", [])
            is_tag_excepted = __is_item_matched__(excepted_tags, finding_tags)

            if (
                not is_account_excepted
                and not is_region_excepted
                and not is_resource_excepted
                and not is_tag_excepted
            ):
                excepted = False
            elif (
                (is_account_excepted or not excepted_accounts)
                and (is_region_excepted or not excepted_regions)
                and (is_resource_excepted or not excepted_resources)
                and (is_tag_excepted or not excepted_tags)
            ):
                excepted = True
        return excepted
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def __is_item_matched__(matched_items, finding_items):
    """
    Check if any of the items in matched_items are present in finding_items.

    Args:
        matched_items (list): List of items to be matched.
        finding_items (str): String to search for matched items.

    Returns:
        bool: True if any of the matched_items are present in finding_items, otherwise False.
    """
    try:
        is_item_matched = False
        if matched_items and (finding_items or finding_items == ""):
            for item in matched_items:
                if item.startswith("*"):
                    item = ".*" + item[1:]
                if re.search(item, finding_items):
                    is_item_matched = True
                    break
        return is_item_matched
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False
