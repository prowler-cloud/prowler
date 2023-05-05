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
                    str: {"Regions": list, "Resources": list, Optional("Tags"): list}
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
                if "Tags" in item:
                    allowlist["Accounts"][item["Accounts"]] = {
                        "Checks": {
                            item["Checks"]: {
                                "Regions": item["Regions"],
                                "Resources": item["Resources"],
                                "Tags": item["Tags"],
                            }
                        }
                    }
                else:
                    allowlist["Accounts"][item["Accounts"]] = {
                        "Checks": {
                            item["Checks"]: {
                                "Regions": item["Regions"],
                                "Resources": item["Resources"],
                            }
                        }
                    }
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
            if is_allowlisted_in_check(
                allowlist, audited_account, check, region, resource, tags
            ):
                return True
        # If there is a *, it affects to all accounts
        if "*" in allowlist["Accounts"]:
            audited_account = "*"
            if is_allowlisted_in_check(
                allowlist, audited_account, check, region, resource, tags
            ):
                return True
        return False
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_check(allowlist, audited_account, check, region, resource, tags):
    try:
        # If there is a *, it affects to all checks
        if "*" in allowlist["Accounts"][audited_account]["Checks"]:
            check = "*"
            if is_allowlisted_in_region(
                allowlist, audited_account, check, region, resource, tags
            ):
                return True
        # Check if there is the specific check
        if check in allowlist["Accounts"][audited_account]["Checks"]:
            if is_allowlisted_in_region(
                allowlist, audited_account, check, region, resource, tags
            ):
                return True
        return False
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)


def is_allowlisted_in_region(allowlist, audited_account, check, region, resource, tags):
    try:
        # If there is a *, it affects to all regions
        if "*" in allowlist["Accounts"][audited_account]["Checks"][check]["Regions"]:
            for elem in allowlist["Accounts"][audited_account]["Checks"][check][
                "Resources"
            ]:
                if is_allowlisted_in_tags(
                    allowlist["Accounts"][audited_account]["Checks"][check],
                    elem,
                    resource,
                    tags,
                ):
                    return True
        # Check if there is the specific region
        if region in allowlist["Accounts"][audited_account]["Checks"][check]["Regions"]:
            for elem in allowlist["Accounts"][audited_account]["Checks"][check][
                "Resources"
            ]:
                if is_allowlisted_in_tags(
                    allowlist["Accounts"][audited_account]["Checks"][check],
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
                for resource_tag in tags:
                    if re.search(allowed_tag, resource_tag):
                        found_allowed_tag = True
                        break

                if not found_allowed_tag:
                    all_allowed_tags_in_resource_tags = False

            return all_allowed_tags_in_resource_tags
        else:
            if re.search(elem, resource):
                return True
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
        )
        sys.exit(1)
