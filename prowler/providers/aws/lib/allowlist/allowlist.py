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
        if audited_account in allowlist["Accounts"]:
            account = audited_account
            if is_allowlisted_in_check(
                allowlist, audited_account, account, check, region, resource, tags
            ):
                return True
        # If there is a *, it affects to all accounts
        if "*" in allowlist["Accounts"]:
            account = "*"
            if is_allowlisted_in_check(
                allowlist, audited_account, account, check, region, resource, tags
            ):
                return True
        return False
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_check(
    allowlist, audited_account, account, check, region, resource, tags
):
    try:
        allowlisted_checks = allowlist["Accounts"][account]["Checks"]
        for allowlisted_check in allowlisted_checks.keys():
            if re.search("^lambda", allowlisted_check):
                mapped_check = re.sub("^lambda", "awslambda", allowlisted_check)
                # we update the dictionary
                allowlisted_checks[mapped_check] = allowlisted_checks.pop(
                    allowlisted_check
                )
                # and the single element
                allowlisted_check = mapped_check

            # Check if there are exceptions
            if is_excepted(
                allowlisted_checks,
                allowlisted_check,
                audited_account,
                region,
                resource,
                tags,
            ):
                return False
            # If there is a *, it affects to all checks
            if "*" == allowlisted_check:
                check = "*"
                if is_allowlisted_in_region(
                    allowlist, account, check, region, resource, tags
                ):
                    return True
            # Check if there is the specific check
            elif check == allowlisted_check:
                if is_allowlisted_in_region(
                    allowlist, account, check, region, resource, tags
                ):
                    return True
            # Check if check is a regex
            elif re.search(allowlisted_check, check):
                if is_allowlisted_in_region(
                    allowlist,
                    account,
                    allowlisted_check,
                    region,
                    resource,
                    tags,
                ):
                    return True
        return False
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_region(allowlist, account, check, region, resource, tags):
    try:
        # If there is a *, it affects to all regions
        if "*" in allowlist["Accounts"][account]["Checks"][check]["Regions"]:
            for elem in allowlist["Accounts"][account]["Checks"][check]["Resources"]:
                if is_allowlisted_in_tags(
                    allowlist["Accounts"][account]["Checks"][check],
                    elem,
                    resource,
                    tags,
                ):
                    return True
        # Check if there is the specific region
        if region in allowlist["Accounts"][account]["Checks"][check]["Regions"]:
            for elem in allowlist["Accounts"][account]["Checks"][check]["Resources"]:
                if is_allowlisted_in_tags(
                    allowlist["Accounts"][account]["Checks"][check],
                    elem,
                    resource,
                    tags,
                ):
                    return True
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_tags(check_allowlist, elem, resource, tags):
    try:
        # Check if it is an *
        if elem == "*":
            elem = ".*"
        # Check if there are allowlisted tags
        if "Tags" in check_allowlist:
            # Check if there are resource tags
            if not tags or not re.search(elem, resource):
                return False

            all_allowed_tags_in_resource_tags = True
            for allowed_tag in check_allowlist["Tags"]:
                found_allowed_tag = False
                if re.search(allowed_tag, tags):
                    found_allowed_tag = True

                if not found_allowed_tag:
                    all_allowed_tags_in_resource_tags = False
                    break

            return all_allowed_tags_in_resource_tags
        else:
            if re.search(elem, resource):
                return True
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_excepted(
    allowlisted_checks, allowlisted_check, audited_account, region, resource, tags
):
    try:
        excepted = False
        is_account_excepted = False
        is_region_excepted = False
        is_resource_excepted = False
        is_tag_excepted = False
        exceptions = allowlisted_checks[allowlisted_check].get("Exceptions")
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
                if tags in excepted_tags:
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
