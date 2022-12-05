from datetime import datetime, timezone
from os import getcwd

import yaml
from lib.logger import logger

timestamp = datetime.today()
timestamp_utc = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
prowler_version = "3.0-beta-21Nov2022"
html_logo_url = "https://github.com/prowler-cloud/prowler/"
html_logo_img = (
    "https://github.com/prowler-cloud/prowler/raw/master/util/html/prowler-logo-new.png"
)

orange_color = "\033[38;5;208m"
banner_color = "\033[1;92m"

# Compliance
compliance_specification_dir = "./compliance"

# AWS services-regions matrix json
aws_services_json_file = "prowler/providers/aws/aws_regions_by_service.json"

default_output_directory = getcwd() + "/output"

output_file_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
timestamp_iso = timestamp.isoformat()
csv_file_suffix = ".csv"
json_file_suffix = ".json"
json_asff_file_suffix = ".asff.json"
html_file_suffix = ".html"
config_yaml = "prowler/config/config.yaml"


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
