import re
import sys
from typing import Any

import yaml
from boto3 import Session
from boto3.dynamodb.conditions import Attr
from schema import Optional, Schema

from prowler.lib.logger import logger
from prowler.lib.outputs.models import unroll_tags

mutelist_schema = Schema(
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


def parse_mutelist_file(
    mutelist_path: str, aws_session: Session = None, aws_account: str = None
):
    try:
        # Check if file is a S3 URI
        if re.search("^s3://([^/]+)/(.*?([^/]+))$", mutelist_path):
            bucket = mutelist_path.split("/")[2]
            key = ("/").join(mutelist_path.split("/")[3:])
            s3_client = aws_session.client("s3")
            mutelist = yaml.safe_load(
                s3_client.get_object(Bucket=bucket, Key=key)["Body"]
            )["Mute List"]
        # Check if file is a Lambda Function ARN
        elif re.search(r"^arn:(\w+):lambda:", mutelist_path):
            lambda_region = mutelist_path.split(":")[3]
            lambda_client = aws_session.client("lambda", region_name=lambda_region)
            lambda_response = lambda_client.invoke(
                FunctionName=mutelist_path, InvocationType="RequestResponse"
            )
            lambda_payload = lambda_response["Payload"].read()
            mutelist = yaml.safe_load(lambda_payload)["Mute List"]
        # Check if file is a DynamoDB ARN
        elif re.search(
            r"^arn:aws(-cn|-us-gov)?:dynamodb:[a-z]{2}-[a-z-]+-[1-9]{1}:[0-9]{12}:table\/[a-zA-Z0-9._-]+$",
            mutelist_path,
        ):
            mutelist = {"Accounts": {}}
            table_region = mutelist_path.split(":")[3]
            dynamodb_resource = aws_session.resource(
                "dynamodb", region_name=table_region
            )
            dynamo_table = dynamodb_resource.Table(mutelist_path.split("/")[1])
            response = dynamo_table.scan(
                FilterExpression=Attr("Accounts").is_in([aws_account, "*"])
            )
            dynamodb_items = response["Items"]
            # Paginate through all results
            while "LastEvaluatedKey" in dynamodb_items:
                response = dynamo_table.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                    FilterExpression=Attr("Accounts").is_in([aws_account, "*"]),
                )
                dynamodb_items.update(response["Items"])
            for item in dynamodb_items:
                # Create mutelist for every item
                mutelist["Accounts"][item["Accounts"]] = {
                    "Checks": {
                        item["Checks"]: {
                            "Regions": item["Regions"],
                            "Resources": item["Resources"],
                        }
                    }
                }
                if "Tags" in item:
                    mutelist["Accounts"][item["Accounts"]]["Checks"][item["Checks"]][
                        "Tags"
                    ] = item["Tags"]
                if "Exceptions" in item:
                    mutelist["Accounts"][item["Accounts"]]["Checks"][item["Checks"]][
                        "Exceptions"
                    ] = item["Exceptions"]
        else:
            with open(mutelist_path) as f:
                mutelist = yaml.safe_load(f)["Mute List"]
        try:
            mutelist_schema.validate(mutelist)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__} -- Mute List YAML is malformed - {error}[{error.__traceback__.tb_lineno}]"
            )
            sys.exit(1)
        return mutelist
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def mutelist_findings(
    global_provider: Any,
    check_findings: list[Any],
):
    # Check if finding is muted
    for finding in check_findings:
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
    return check_findings


def is_muted(
    mutelist: dict,
    audited_account: str,
    check: str,
    finding_region: str,
    finding_resource: str,
    finding_tags,
):
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
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_muted_in_check(
    muted_checks,
    audited_account,
    check,
    finding_region,
    finding_resource,
    finding_tags,
):
    try:
        # Default value is not muted
        is_check_muted = False

        for muted_check, muted_check_info in muted_checks.items():
            # map lambda to awslambda
            muted_check = re.sub("^lambda", "awslambda", muted_check)

            # Check if the finding is excepted
            exceptions = muted_check_info.get("Exceptions")
            if is_excepted(
                exceptions,
                audited_account,
                finding_region,
                finding_resource,
                finding_tags,
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
            if (
                "*" == muted_check
                or check == muted_check
                or re.search(muted_check, check)
            ):
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
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_muted_in_region(
    mutelist_regions,
    finding_region,
):
    try:
        return __is_item_matched__(mutelist_regions, finding_region)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_muted_in_tags(muted_tags, finding_tags):
    try:
        return __is_item_matched__(muted_tags, finding_tags)
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_muted_in_resource(muted_resources, finding_resource):
    try:
        return __is_item_matched__(muted_resources, finding_resource)

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
