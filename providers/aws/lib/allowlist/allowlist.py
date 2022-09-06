import re
import sys

import yaml

from lib.logger import logger


def parse_allowlist_file(session, allowlist_file):
    try:
        # Check if file is a S3 URI
        if re.search("^s3://([^/]+)/(.*?([^/]+))$", allowlist_file):
            bucket = allowlist_file.split("/")[2]
            key = ("/").join(allowlist_file.split("/")[3:])
            s3_client = session.client("s3")
            allowlist = yaml.safe_load(
                s3_client.get_object(Bucket=bucket, Key=key)["Body"]
            )["Allowlist"]
        else:
            with open(allowlist_file) as f:
                allowlist = yaml.safe_load(f)["Allowlist"]
        return allowlist
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit()


def is_allowlisted(allowlist, account, check, region, resource):
    try:
        if account in allowlist["Accounts"]:
            if is_allowlisted_in_check(allowlist, account, check, region, resource):
                return True
        # If there is a *, it affects to all accounts
        if "*" in allowlist["Accounts"]:
            account = "*"
            if is_allowlisted_in_check(allowlist, account, check, region, resource):
                return True
        return False
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit()


def is_allowlisted_in_check(allowlist, account, check, region, resource):
    # If there is a *, it affects to all checks
    if "*" in allowlist["Accounts"][account]["Checks"]:
        check = "*"
        if is_allowlisted_in_region(allowlist, account, check, region, resource):
            return True
    # Check if there is the specific check
    if check in allowlist["Accounts"][account]["Checks"]:
        if is_allowlisted_in_region(allowlist, account, check, region, resource):
            return True
    return False


def is_allowlisted_in_region(allowlist, account, check, region, resource):
    # If there is a *, it affects to all regions
    if "*" in allowlist["Accounts"][account]["Checks"][check]["Regions"]:
        for elem in allowlist["Accounts"][account]["Checks"][check]["Resources"]:
            if re.search(elem, resource):
                return True
    # Check if there is the specific region
    if region in allowlist["Accounts"][account]["Checks"][check]["Regions"]:
        for elem in allowlist["Accounts"][account]["Checks"][check]["Resources"]:
            if re.search(elem, resource):
                return True
