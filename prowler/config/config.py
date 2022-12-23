import os
from datetime import datetime, timezone
from os import getcwd

import yaml

from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file

timestamp = datetime.today()
timestamp_utc = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
prowler_version = "3.0.1"
html_logo_url = "https://github.com/prowler-cloud/prowler/"
html_logo_img = "https://user-images.githubusercontent.com/3985464/113734260-7ba06900-96fb-11eb-82bc-d4f68a1e2710.png"

orange_color = "\033[38;5;208m"
banner_color = "\033[1;92m"

# Compliance
compliance_specification_dir = "./compliance"

# AWS services-regions matrix json
aws_services_json_file = "aws_regions_by_service.json"

default_output_directory = getcwd() + "/output"

output_file_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
timestamp_iso = timestamp.isoformat(sep=" ", timespec="seconds")
csv_file_suffix = ".csv"
json_file_suffix = ".json"
json_asff_file_suffix = ".asff.json"
html_file_suffix = ".html"
config_yaml = f"{os.path.dirname(os.path.realpath(__file__))}/config.yaml"


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


def get_aws_available_regions():
    try:
        actual_directory = ("/").join(
            os.path.dirname(os.path.realpath(__file__)).split("/")[:-1]
        )
        f = open_file(f"{actual_directory}/providers/aws/{aws_services_json_file}")
        data = parse_json_file(f)

        regions = set()
        for service in data["services"].values():
            for partition in service["regions"]:
                for item in service["regions"][partition]:
                    regions.add(item)
        return list(regions)
    except Exception as error:
        logger.error(f"{error.__class__.__name__}: {error}")
        return []
