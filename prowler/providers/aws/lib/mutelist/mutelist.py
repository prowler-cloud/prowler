import re
import sys
from typing import Any

import yaml
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


def parse_mutelist_file(audit_info, mutelist_file):
    try:
        # Check if file is a S3 URI
        if re.search("^s3://([^/]+)/(.*?([^/]+))$", mutelist_file):
            bucket = mutelist_file.split("/")[2]
            key = ("/").join(mutelist_file.split("/")[3:])
            s3_client = audit_info.audit_session.client("s3")
            mutelist = yaml.safe_load(
                s3_client.get_object(Bucket=bucket, Key=key)["Body"]
            )["Mute List"]
        # Check if file is a Lambda Function ARN
        elif re.search(r"^arn:(\w+):lambda:", mutelist_file):
            lambda_region = mutelist_file.split(":")[3]
            lambda_client = audit_info.audit_session.client(
                "lambda", region_name=lambda_region
            )
            lambda_response = lambda_client.invoke(
                FunctionName=mutelist_file, InvocationType="RequestResponse"
            )
            lambda_payload = lambda_response["Payload"].read()
            mutelist = yaml.safe_load(lambda_payload)["Mute List"]
        # Check if file is a DynamoDB ARN
        elif re.search(
            r"^arn:aws(-cn|-us-gov)?:dynamodb:[a-z]{2}-[a-z-]+-[1-9]{1}:[0-9]{12}:table\/[a-zA-Z0-9._-]+$",
            mutelist_file,
        ):
            mutelist = {"Accounts": {}}
            table_region = mutelist_file.split(":")[3]
            dynamodb_resource = audit_info.audit_session.resource(
                "dynamodb", region_name=table_region
            )
            dynamo_table = dynamodb_resource.Table(mutelist_file.split("/")[1])
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
            with open(mutelist_file) as f:
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
    mutelist: dict,
    audited_account: str,
    check_findings: [Any],
):
    # Check if finding is muted
    for finding in check_findings:
        if is_muted(
            mutelist,
            audited_account,
            finding.check_metadata.CheckID,
            finding.region,
            finding.resource_id,
            unroll_tags(finding.resource_tags),
        ):
            finding.status = "MUTED"
    return check_findings


def is_muted(
    mutelist: dict, audited_account: str, check: str, region: str, resource: str, tags
):
    try:
        muted_checks = {}
        # By default is not muted
        is_finding_muted = False
        # First set account key from mutelist dict
        if audited_account in mutelist["Accounts"]:
            muted_checks = mutelist["Accounts"][audited_account]["Checks"]
        # If there is a *, it affects to all accounts
        # This cannot be elif since in the case of * and single accounts we
        # want to merge muted checks from * to the other accounts check list
        if "*" in mutelist["Accounts"]:
            checks_multi_account = mutelist["Accounts"]["*"]["Checks"]
            muted_checks.update(checks_multi_account)
        # Test if it is muted
        if is_muted_in_check(
            muted_checks,
            audited_account,
            audited_account,
            check,
            region,
            resource,
            tags,
        ):
            is_finding_muted = True

        return is_finding_muted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_muted_in_check(
    muted_checks, audited_account, account, check, region, resource, tags
):
    try:
        # Default value is not muted
        is_check_muted = False
        for muted_check, muted_check_info in muted_checks.items():
            # map lambda to awslambda
            muted_check = re.sub("^lambda", "awslambda", muted_check)
            # extract the exceptions
            exceptions = muted_check_info.get("Exceptions")
            # Check if there are exceptions
            if is_excepted(
                exceptions,
                audited_account,
                region,
                resource,
                tags,
            ):
                # Break loop and return default value since is excepted
                break

            muted_regions = muted_check_info.get("Regions")
            muted_resources = muted_check_info.get("Resources")
            muted_tags = muted_check_info.get("Tags")
            # If there is a *, it affects to all checks
            if (
                "*" == muted_check
                or check == muted_check
                or re.search(muted_check, check)
            ):
                if is_muted_in_region(
                    muted_regions,
                    muted_resources,
                    muted_tags,
                    region,
                    resource,
                    tags,
                ):
                    is_check_muted = True

        return is_check_muted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_muted_in_region(
    mutelist_regions, mutelist_resources, muted_tags, region, resource, tags
):
    try:
        # By default is not muted
        is_region_muted = False
        # If there is a *, it affects to all regions
        if "*" in mutelist_regions or region in mutelist_regions:
            for elem in mutelist_resources:
                if is_muted_in_tags(
                    muted_tags,
                    elem,
                    resource,
                    tags,
                ):
                    is_region_muted = True
                    # if we find the element there is no point in continuing with the loop
                    break

            return is_region_muted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_muted_in_tags(muted_tags, elem, resource, tags):
    try:
        # By default is not muted
        is_tag_muted = False
        # Check if it is an *
        if elem == "*":
            elem = ".*"
        # Check if there are muted tags
        if muted_tags:
            for muted_tag in muted_tags:
                if re.search(muted_tag, tags):
                    is_tag_muted = True
                    break

        else:
            if re.search(elem, resource):
                is_tag_muted = True

        return is_tag_muted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_excepted(exceptions, audited_account, region, resource, tags):
    try:
        excepted = False
        is_account_excepted = False
        is_region_excepted = False
        is_resource_excepted = False
        is_tag_excepted = False
        if exceptions:
            excepted_accounts = exceptions.get("Accounts", [])
            excepted_regions = exceptions.get("Regions", [])
            excepted_resources = exceptions.get("Resources", [])
            excepted_tags = exceptions.get("Tags", [])
            if exceptions:
                if audited_account in excepted_accounts:
                    is_account_excepted = True
                if region in excepted_regions:
                    is_region_excepted = True
                for excepted_resource in excepted_resources:
                    if re.search(excepted_resource, resource):
                        is_resource_excepted = True
                for tag in excepted_tags:
                    if tag in tags:
                        is_tag_excepted = True
                if (
                    (
                        (excepted_accounts and is_account_excepted)
                        or not excepted_accounts
                    )
                    and (
                        (excepted_regions and is_region_excepted)
                        or not excepted_regions
                    )
                    and (
                        (excepted_resources and is_resource_excepted)
                        or not excepted_resources
                    )
                    and ((excepted_tags and is_tag_excepted) or not excepted_tags)
                ):
                    excepted = True
        return excepted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)
