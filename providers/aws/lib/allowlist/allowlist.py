import re

import yaml


def is_allowlisted(allowlist_file, account, check, region, resource):
    with open(allowlist_file) as f:
        allowlist = yaml.safe_load(f)["Allowlist"]
    if account in allowlist["Accounts"]:
        if is_allowlisted_in_check(allowlist, account, check, region, resource):
            return True
    # If there is a *, it affects to all accounts
    if "*" in allowlist["Accounts"]:
        account = "*"
        if is_allowlisted_in_check(allowlist, account, check, region, resource):
            return True
    return False


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
