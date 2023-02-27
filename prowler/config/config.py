import os
import pathlib
from datetime import datetime, timezone
from os import getcwd

import yaml

from prowler.lib.logger import logger

timestamp = datetime.today()
timestamp_utc = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
prowler_version = "3.2.2"
html_logo_url = "https://github.com/prowler-cloud/prowler/"
html_logo_img = "https://user-images.githubusercontent.com/3985464/113734260-7ba06900-96fb-11eb-82bc-d4f68a1e2710.png"

orange_color = "\033[38;5;208m"
banner_color = "\033[1;92m"

# Compliance
compliance_specification_dir = "./compliance"
available_compliance_frameworks = [
    "ens_rd2022_aws",
    "cis_1.4_aws",
    "cis_1.5_aws",
    "aws_audit_manager_control_tower_guardrails_aws",
    "aws_foundational_security_best_practices_aws",
    "cisa_aws",
    "fedramp_low_revision_4_aws",
    "fedramp_moderate_revision_4_aws",
    "ffiec_aws",
    "gdpr_aws",
    "gxp_eu_annex_11_aws",
    "gxp_21_cfr_part_11_aws",
    "hipaa_aws",
    "nist_800_53_revision_4_aws",
    "nist_800_53_revision_5_aws",
    "nist_800_171_revision_2_aws",
    "nist_csf_1.1_aws",
    "pci_3.2.1_aws",
    "rbi_cyber_security_framework_aws",
    "soc2_aws",
]
# AWS services-regions matrix json
aws_services_json_file = "aws_regions_by_service.json"

default_output_directory = getcwd() + "/output"

output_file_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
timestamp_iso = timestamp.isoformat(sep=" ", timespec="seconds")
csv_file_suffix = ".csv"
json_file_suffix = ".json"
json_asff_file_suffix = ".asff.json"
html_file_suffix = ".html"
config_yaml = f"{pathlib.Path(os.path.dirname(os.path.realpath(__file__)))}/config.yaml"


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
