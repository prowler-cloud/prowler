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
