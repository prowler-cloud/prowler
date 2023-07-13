import re
import sys

import yaml
from boto3.dynamodb.conditions import Attr
from schema import Optional, Schema

from prowler.lib.logger import logger

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


def is_allowlisted(allowlist, audited_account, check, region, resource, tags):
    try:
        allowlisted_checks = {}
        # By default is not allowlisted
        is_finding_allowlisted = False
        # First set account key from allowlist dict
        if audited_account in allowlist["Accounts"]:
            allowlisted_checks = allowlist["Accounts"][audited_account]["Checks"]

        # If there is a *, it affects to all accounts
        # This cannot be elif since in the case of * and single accounts we
        # want to merge allowlisted checks from * to the other accounts check list
        if "*" in allowlist["Accounts"]:
            checks_multi_account = allowlist["Accounts"]["*"]["Checks"]
            allowlisted_checks.update(checks_multi_account)
        # Test if it is allowlisted
        if is_allowlisted_in_check(
            allowlisted_checks,
            audited_account,
            audited_account,
            check,
            region,
            resource,
            tags,
        ):
            is_finding_allowlisted = True

        return is_finding_allowlisted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_check(
    allowlisted_checks, audited_account, account, check, region, resource, tags
):
    try:
        # Default value is not allowlisted
        is_check_allowlisted = False
        for allowlisted_check, allowlisted_check_info in allowlisted_checks.items():
            # map lambda to awslambda
            allowlisted_check = re.sub("^lambda", "awslambda", allowlisted_check)
            # extract the exceptions
            exceptions = allowlisted_check_info.get("Exceptions")
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

            allowlisted_regions = allowlisted_check_info.get("Regions")
            allowlisted_resources = allowlisted_check_info.get("Resources")
            allowlisted_tags = allowlisted_check_info.get("Tags")
            # If there is a *, it affects to all checks
            if (
                "*" == allowlisted_check
                or check == allowlisted_check
                or re.search(allowlisted_check, check)
            ):
                if is_allowlisted_in_region(
                    allowlisted_regions,
                    allowlisted_resources,
                    allowlisted_tags,
                    region,
                    resource,
                    tags,
                ):
                    is_check_allowlisted = True

        return is_check_allowlisted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_region(
    allowlist_regions, allowlist_resources, allowlisted_tags, region, resource, tags
):
    try:
        # By default is not allowlisted
        is_region_allowlisted = False
        # If there is a *, it affects to all regions
        if "*" in allowlist_regions or region in allowlist_regions:
            for elem in allowlist_resources:
                if is_allowlisted_in_tags(
                    allowlisted_tags,
                    elem,
                    resource,
                    tags,
                ):
                    is_region_allowlisted = True
                    # if we find the element there is no point in continuing with the loop
                    break

            return is_region_allowlisted
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_tags(allowlisted_tags, elem, resource, tags):
    try:
        # By default is not allowlisted
        is_tag_allowlisted = False
        # Check if it is an *
        if elem == "*":
            elem = ".*"
        # Check if there are allowlisted tags
        if allowlisted_tags:
            for allowlisted_tag in allowlisted_tags:
                if re.search(allowlisted_tag, tags):
                    is_tag_allowlisted = True
                    break

        else:
            if re.search(elem, resource):
                is_tag_allowlisted = True

        return is_tag_allowlisted
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
