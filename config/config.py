import re
from datetime import datetime, timezone
from os import getcwd

import yaml

timestamp = datetime.today()
timestamp_utc = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
prowler_version = "3.0-beta-08Aug2022"

# Groups
groups_file = "groups.json"

# AWS services-regions matrix json
aws_services_json_file = "providers/aws/aws_regions_by_service.json"

default_output_directory = getcwd() + "/output"

output_file_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
timestamp_iso = timestamp.isoformat()
csv_file_suffix = ".csv"
json_file_suffix = ".json"
json_asff_file_suffix = ".asff.json"
config_yaml = "providers/aws/config.yaml"
allowlist_yaml = "providers/aws/allowlist.yaml"


def change_config_var(variable, value):
    with open(config_yaml) as f:
        doc = yaml.safe_load(f)

    doc[variable] = value

    with open(config_yaml, "w") as f:
        yaml.dump(doc, f)


def get_config_var(variable):
    with open(config_yaml) as f:
        doc = yaml.safe_load(f)

    return doc[variable]


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
