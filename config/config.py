from datetime import datetime, timezone
from os import getcwd

import yaml

from lib.logger import logger

timestamp = datetime.today()
timestamp_utc = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
prowler_version = "3.0-beta-08Aug2022"

# Groups
groups_file = "groups.json"

# Compliance
compliance_specification_dir = "./compliance"

# AWS services-regions matrix json
aws_services_json_file = "providers/aws/aws_regions_by_service.json"

default_output_directory = getcwd() + "/output"

output_file_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
timestamp_iso = timestamp.isoformat()
csv_file_suffix = ".csv"
json_file_suffix = ".json"
json_asff_file_suffix = ".asff.json"
config_yaml = "providers/aws/config.yaml"


def change_config_var(variable, value):
    try:
        with open(config_yaml) as f:
            doc = yaml.safe_load(f)

        doc[variable] = value

        with open(config_yaml, "w") as f:
            yaml.dump(doc, f)
    except Exception as error:
        logger.error(f"{error.__class__.__name__}: {error}")


def get_config_var(variable):
    try:
        with open(config_yaml) as f:
            doc = yaml.safe_load(f)

        return doc[variable]
    except Exception as error:
        logger.error(f"{error.__class__.__name__}: {error}")
        return ""
