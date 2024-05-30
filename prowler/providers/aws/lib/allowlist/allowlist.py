import re
import sys
from typing import Any

import yaml
from boto3.dynamodb.conditions import Attr
from schema import Optional, Schema

from prowler.lib.logger import logger
from prowler.lib.outputs.models import unroll_tags

allowlist_schema = Schema(
    {
        "Accounts": {
            str: {
                "Checks": {
                    str: {
                        "Regions": list,
                        "Resources": list,
                        Optional("Tags"): list,
                        Optional("Exceptions"): {
                            Optional("Accounts"): list,
                            Optional("Regions"): list,
                            Optional("Resources"): list,
                            Optional("Tags"): list,
                        },
                    }
                }
            }
        }
    }
)


def parse_allowlist_file(audit_info, allowlist_file):
    try:
        # Check if file is a S3 URI
        if re.search("^s3://([^/]+)/(.*?([^/]+))$", allowlist_file):
            bucket = allowlist_file.split("/")[2]
            key = ("/").join(allowlist_file.split("/")[3:])
            s3_client = audit_info.audit_session.client("s3")
            allowlist = yaml.safe_load(
                s3_client.get_object(Bucket=bucket, Key=key)["Body"]
            )["Allowlist"]
        # Check if file is a Lambda Function ARN
        elif re.search(r"^arn:(\w+):lambda:", allowlist_file):
            lambda_region = allowlist_file.split(":")[3]
            lambda_client = audit_info.audit_session.client(
                "lambda", region_name=lambda_region
            )
            lambda_response = lambda_client.invoke(
                FunctionName=allowlist_file, InvocationType="RequestResponse"
            )
            lambda_payload = lambda_response["Payload"].read()
            allowlist = yaml.safe_load(lambda_payload)["Allowlist"]
        # Check if file is a DynamoDB ARN
        elif re.search(
            r"^arn:aws(-cn|-us-gov)?:dynamodb:[a-z]{2}-[a-z-]+-[1-9]{1}:[0-9]{12}:table\/[a-zA-Z0-9._-]+$",
            allowlist_file,
        ):
            allowlist = {"Accounts": {}}
            table_region = allowlist_file.split(":")[3]
            dynamodb_resource = audit_info.audit_session.resource(
                "dynamodb", region_name=table_region
            )
            dynamo_table = dynamodb_resource.Table(allowlist_file.split("/")[1])
            response = dynamo_table.scan(
                FilterExpression=Attr("Accounts").is_in(
                    [audit_info.audited_account, "*"]
                )
            )
            dynamodb_items = response["Items"]
            # Paginate through all results
            while "LastEvaluatedKey" in dynamodb_items:
                response = dynamo_table.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                    FilterExpression=Attr("Accounts").is_in(
                        [audit_info.audited_account, "*"]
                    ),
                )
                dynamodb_items.update(response["Items"])
            for item in dynamodb_items:
                # Create allowlist for every item
                allowlist["Accounts"][item["Accounts"]] = {
                    "Checks": {
                        item["Checks"]: {
                            "Regions": item["Regions"],
                            "Resources": item["Resources"],
                        }
                    }
                }
                if "Tags" in item:
                    allowlist["Accounts"][item["Accounts"]]["Checks"][item["Checks"]][
                        "Tags"
                    ] = item["Tags"]
                if "Exceptions" in item:
                    allowlist["Accounts"][item["Accounts"]]["Checks"][item["Checks"]][
                        "Exceptions"
                    ] = item["Exceptions"]
        else:
            with open(allowlist_file) as f:
                allowlist = yaml.safe_load(f)["Allowlist"]
        try:
            allowlist_schema.validate(allowlist)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__} -- Allowlist YAML is malformed - {error}[{error.__traceback__.tb_lineno}]"
            )
            sys.exit(1)
        return allowlist
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def allowlist_findings(
    allowlist: dict,
    audited_account: str,
    check_findings: list[Any],
) -> list[Any]:
    # Check if finding is allowlisted
    for finding in check_findings:
        if is_allowlisted(
            allowlist,
            audited_account,
            finding.check_metadata.CheckID,
            finding.region,
            finding.resource_id,
            unroll_tags(finding.resource_tags),
        ):
            finding.status = "WARNING"
    return check_findings


def is_allowlisted(
    allowlist: dict,
    audited_account: str,
    check: str,
    finding_region: str,
    finding_resource: str,
    finding_tags,
) -> bool:
    """
    Check if the provided finding is allowlisted for the audited account, check, region, resource and tags.

    Args:
        mutelist (dict): Dictionary containing information about allowlisted checks for different accounts.
        audited_account (str): The account being audited.
        check (str): The check to be evaluated for allowlisting.
        finding_region (str): The region where the finding occurred.
        finding_resource (str): The resource related to the finding.
        finding_tags: The tags associated with the finding.

    Returns:
        bool: True if the finding is allowlisted for the audited account, check, region, resource and tags., otherwise False.
    """
    try:
        # By default is not allowlisted
        is_finding_allowlisted = False

        # We always check all the accounts present in the allowlist
        # if one allowlists the finding we set the finding as allowlisted
        for account in allowlist["Accounts"]:
            if account == audited_account or account == "*":
                if is_allowlisted_in_check(
                    allowlist["Accounts"][account]["Checks"],
                    audited_account,
                    check,
                    finding_region,
                    finding_resource,
                    finding_tags,
                ):
                    is_finding_allowlisted = True
                    break

        return is_finding_allowlisted
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_allowlisted_in_check(
    allowlisted_checks,
    audited_account,
    check,
    finding_region,
    finding_resource,
    finding_tags,
) -> bool:
    """
    Check if the provided check is allowlisted.

    Args:
        allowlisted_checks (dict): Dictionary containing information about allowlisted checks.
        audited_account (str): The account to be audited.
        check (str): The check to be evaluated for allowlisting.
        finding_region (str): The region where the finding occurred.
        finding_resource (str): The resource related to the finding.
        finding_tags (str): The tags associated with the finding.

    Returns:
        bool: True if the check is allowlisted, otherwise False.
    """
    try:
        # Default value is not allowlisted
        is_check_allowlisted = False

        for allowlisted_check, allowlisted_check_info in allowlisted_checks.items():
            # map lambda to awslambda
            allowlisted_check = re.sub("^lambda", "awslambda", allowlisted_check)

            check_match = (
                "*" == allowlisted_check
                or check == allowlisted_check
                or re.search(allowlisted_check, check)
            )

            # Check if the finding is excepted
            exceptions = allowlisted_check_info.get("Exceptions")
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

            allowlisted_regions = allowlisted_check_info.get("Regions")
            allowlisted_resources = allowlisted_check_info.get("Resources")
            allowlisted_tags = allowlisted_check_info.get("Tags", "*")
            # We need to set the allowlisted_tags if None, "" or [], so the falsy helps
            if not allowlisted_tags:
                allowlisted_tags = "*"

            # If there is a *, it affects to all checks
            if check_match:
                allowlisted_in_check = True
                allowlisted_in_region = is_allowlisted_in_region(
                    allowlisted_regions, finding_region
                )
                allowlisted_in_resource = is_allowlisted_in_resource(
                    allowlisted_resources, finding_resource
                )
                allowlisted_in_tags = is_allowlisted_in_tags(
                    allowlisted_tags, finding_tags
                )

                # For a finding to be allowlisted requires the following set to True:
                # - allowlisted_in_check -> True
                # - allowlisted_in_region -> True
                # - allowlisted_in_tags -> True
                # - allowlisted_in_resource -> True
                # - excepted -> False

                if (
                    allowlisted_in_check
                    and allowlisted_in_region
                    and allowlisted_in_tags
                    and allowlisted_in_resource
                ):
                    is_check_allowlisted = True

        return is_check_allowlisted
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_allowlisted_in_region(
    allowlisted_regions,
    finding_region,
) -> bool:
    """
    Check if the finding_region is present in the allowlisted_regions.

    Args:
        allowlisted_regions (list): List of regions in the allowlist.
        finding_region (str): Region to check if it is allowlisted.

    Returns:
        bool: True if the finding_region is present in any of the allowlisted_regions, otherwise False.
    """
    try:
        return __is_item_matched__(allowlisted_regions, finding_region)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_allowlisted_in_tags(allowlisted_tags, finding_tags) -> bool:
    """
    Check if any of the allowlisted tags are present in the finding tags.

    Args:
        allowlisted_tags (list): List of allowlisted tags to be checked.
        finding_tags (str): String containing tags to search for allowlisted tags.

    Returns:
        bool: True if any of the allowlisted tags are present in the finding tags, otherwise False.
    """
    try:
        return __is_item_matched__(allowlisted_tags, finding_tags)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        return False


def is_allowlisted_in_resource(allowlisted_resources, finding_resource) -> bool:
    """
    Check if any of the allowlisted_resources are present in the finding_resource.

    Args:
        allowlisted_resources (list): List of allowlisted resources to be checked.
        finding_resource (str): Resource to search for allowlisted resources.

    Returns:
        bool: True if any of the allowlisted_resources are present in the finding_resource, otherwise False.
    """
    try:
        return __is_item_matched__(allowlisted_resources, finding_resource)

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
        # If something unexpected happens return not matched, thus False
        return False
