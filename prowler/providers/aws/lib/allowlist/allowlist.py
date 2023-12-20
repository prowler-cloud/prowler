import re
import sys
from typing import Any

import yaml
from boto3.dynamodb.conditions import Attr
from schema import Optional, Schema

from prowler.lib.logger import logger
from prowler.lib.outputs.models import unroll_tags

allowlist_base_fields = ["Regions", "Resources", "Tags"]
allowlist_exceptions_fields = allowlist_base_fields + ["Accounts"]

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
    check_findings: [Any],
):
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
):
    try:
        allowlisted_checks = {}
        # By default is not allowlisted
        is_finding_allowlisted = False
        # First set account key from allowlist dict
        if audited_account != "*" and audited_account in allowlist["Accounts"]:
            allowlisted_checks = allowlist["Accounts"][audited_account]["Checks"]
        # If there is a *, it affects to all accounts
        # This cannot be elif since in the case of * and single accounts we
        # want to merge allowlisted checks from * to the other accounts check list
        if "*" in allowlist["Accounts"]:
            allowlisted_checks_multi_account = allowlist["Accounts"]["*"]["Checks"]

            if allowlisted_checks and allowlisted_checks_multi_account:
                allowlisted_checks = __merge_allowlist_checks_dictionaries__(
                    check,
                    allowlisted_checks,
                    allowlisted_checks_multi_account,
                )
            else:
                allowlisted_checks.update(allowlisted_checks_multi_account)

        # Test if it is allowlisted
        if is_allowlisted_in_check(
            allowlisted_checks,
            audited_account,
            check,
            finding_region,
            finding_resource,
            finding_tags,
        ):
            is_finding_allowlisted = True

        return is_finding_allowlisted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_check(
    allowlisted_checks,
    audited_account,
    check,
    finding_region,
    finding_resource,
    finding_tags,
):
    try:
        # Default value is not allowlisted
        is_check_allowlisted = False

        for allowlisted_check, allowlisted_check_info in allowlisted_checks.items():
            # map lambda to awslambda
            allowlisted_check = re.sub("^lambda", "awslambda", allowlisted_check)

            # Check if the finding is excepted
            exceptions = allowlisted_check_info.get("Exceptions")
            if is_excepted(
                exceptions,
                audited_account,
                finding_region,
                finding_resource,
                finding_tags,
            ):
                # Break loop and return default value since is excepted
                break

            allowlisted_regions = allowlisted_check_info.get("Regions")
            allowlisted_resources = allowlisted_check_info.get("Resources")
            allowlisted_tags = allowlisted_check_info.get("Tags")
            # If there is a *, it affects to all checks
            if (
                "*" == allowlisted_check
                or check == allowlisted_check
                or re.search(allowlisted_check, check)
            ):
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
                # - allowlisted_in_tags -> True or allowlisted_in_resource -> True
                # - excepted -> False

                if (
                    allowlisted_in_check
                    and allowlisted_in_region
                    and (allowlisted_in_tags or allowlisted_in_resource)
                ):
                    is_check_allowlisted = True

        return is_check_allowlisted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_region(
    allowlisted_regions,
    finding_region,
):
    try:
        return __is_item_matched__(allowlisted_regions, finding_region)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_tags(allowlisted_tags, finding_tags):
    try:
        return __is_item_matched__(allowlisted_tags, finding_tags)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_resource(allowlisted_resources, finding_resource):
    try:
        return __is_item_matched__(allowlisted_resources, finding_resource)

    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_excepted(
    exceptions,
    audited_account,
    finding_region,
    finding_resource,
    finding_tags,
):
    """is_excepted returns True if the account, region, resource and tags are excepted"""
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
                is_account_excepted
                and is_region_excepted
                and is_resource_excepted
                and is_tag_excepted
            ):
                excepted = True
        return excepted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def __is_item_matched__(matched_items, finding_items):
    """__is_item_matched__ return True if any of the matched_items are present in the finding_items, otherwise returns False."""
    try:
        is_item_matched = False
        if matched_items and (finding_items or finding_items == ""):
            for item in matched_items:
                if item == "*":
                    item = ".*"
                if re.search(item, finding_items):
                    is_item_matched = True
                    break
        return is_item_matched
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def __merge_allowlist_checks_dictionaries__(
    check: str,
    allowlisted_checks_single_account: dict,
    allowlisted_checks_multi_account: dict,
):
    """__merge_allowlist_checks_dict__ returns a merged dictorionary.

    Example:
    allowlisted_checks_single_account = {
        "check_test_1": {
            "Regions": ["eu-west-1"],
            "Resources": ["resource_1", "resource_2"],
        },
    }
    allowlisted_checks_multi_account = {
        "check_test_1": {
            "Regions": ["*"],
            "Resources": ["resource_3"],
        }
    }

    __merge_allowlist_checks_dict__(allowlisted_checks_single_account, allowlisted_checks_multi_account) returns
    {
        "check_test_1": {
            "Regions": ["*"],
            "Resources": ["resource_1", "resource_2", "resource_3"],
        },
    }

    """
    # Empty allowlist
    merged_dict = {check: {"Regions": [], "Resources": []}}
    # First merge empty allowlist with the allowlisted_checks_single_account
    merged_dict = __merge_allowlist_dict__(
        check, merged_dict, allowlisted_checks_single_account
    )
    # Then merge the allowlisted_checks_multi_account with the previous one
    merged_dict = __merge_allowlist_dict__(
        check, merged_dict, allowlisted_checks_multi_account
    )

    return merged_dict


def __merge_allowlist_dict__(check: str, merged_dict: dict, to_merge_dict: dict):
    """__merge_allowlist_dict__ returns a merged allowlist based if the Regions or Resources has * or not."""
    if to_merge_dict and check in to_merge_dict:
        for key, value in to_merge_dict[check].items():
            # Handle Base fields
            if key in allowlist_base_fields:
                # Key Tags is optional, so create it if present
                if key == "Tags":
                    merged_dict[check]["Tags"] = []
                if "*" in value:
                    merged_dict[check][key] = ["*"]
                else:
                    merged_dict[check][key].extend(value)
                    merged_dict[check][key] = list(
                        dict.fromkeys(merged_dict[check][key])
                    )
                    merged_dict[check][key].sort()
    return merged_dict
