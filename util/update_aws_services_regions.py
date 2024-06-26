import json
import logging
import os
import sys

import boto3

# Logging config
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
    level=logging.INFO,
)

regions_by_service = {"services": {}}

logging.info("Recovering AWS Regions by Service")
client = boto3.client("ssm", region_name="us-east-1")
get_parameters_by_path_paginator = client.get_paginator("get_parameters_by_path")
# Get all AWS Available Services
for page in get_parameters_by_path_paginator.paginate(
    Path="/aws/service/global-infrastructure/services"
):
    for service in page["Parameters"]:
        regions_by_service["services"][service["Value"]] = {}
        # Get all AWS Regions for the specific service
        regions = {"aws": [], "aws-cn": [], "aws-us-gov": []}
        for page in get_parameters_by_path_paginator.paginate(
            Path="/aws/service/global-infrastructure/services/"
            + service["Value"]
            + "/regions"
        ):
            for region in page["Parameters"]:
                if "cn" in region["Value"]:
                    regions["aws-cn"].append(region["Value"])
                elif "gov" in region["Value"]:
                    regions["aws-us-gov"].append(region["Value"])
                else:
                    regions["aws"].append(region["Value"])
                # Sort regions per partition
                regions["aws"] = sorted(regions["aws"])
                regions["aws-cn"] = sorted(regions["aws-cn"])
                regions["aws-us-gov"] = sorted(regions["aws-us-gov"])
        regions_by_service["services"][service["Value"]]["regions"] = regions

# Include the regions for the subservices and the services not present
logging.info("Updating subservices and the services not present in the original matrix")
# macie2 --> macie
regions_by_service["services"]["macie2"] = regions_by_service["services"]["macie"]
# cognito --> cognito-idp
regions_by_service["services"]["cognito"] = regions_by_service["services"][
    "cognito-idp"
]
# opensearch --> es
regions_by_service["services"]["opensearch"] = regions_by_service["services"]["es"]
# elbv2 --> elb
regions_by_service["services"]["elbv2"] = regions_by_service["services"]["elb"]
# wafv2 --> waf
regions_by_service["services"]["wafv2"] = regions_by_service["services"]["waf"]
# wellarchitected --> wellarchitectedtool
regions_by_service["services"]["wellarchitected"] = regions_by_service["services"][
    "wellarchitectedtool"
]

# Write to file
parsed_matrix_regions_aws = f"{os.path.dirname(os.path.realpath(__name__))}/prowler/providers/aws/aws_regions_by_service.json"
logging.info(f"Writing {parsed_matrix_regions_aws}")
with open(parsed_matrix_regions_aws, "w") as outfile:
    json.dump(regions_by_service, outfile, indent=2, sort_keys=True)
