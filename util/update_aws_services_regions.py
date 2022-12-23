import json
import logging
import os
import sys
from urllib import request

aws_services_json_url = (
    "https://api.regional-table.region-services.aws.a2z.com/index.json"
)

# Logging config
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
    level=logging.INFO,
)

# JSON files
with request.urlopen(aws_services_json_url) as url:  # Get the AWS regions matrix online
    logging.info(f"Downloading JSON from {aws_services_json_url}")
    original_matrix_regions_aws = json.loads(url.read().decode())
parsed_matrix_regions_aws = f"{os.path.dirname(os.path.realpath(__name__))}/prowler/providers/aws/aws_regions_by_service.json"


# JSON objects
regions_by_service = {}
services = {}
old_service = ""

logging.info("Recovering AWS Regions by Service")
# Iterating through the json list
for item in original_matrix_regions_aws["prices"]:
    service = item["id"].split(":")[0]
    region = item["id"].split(":")[1]
    # Init regions for the new service
    if service != old_service:
        regions_dict = {}
        # Store the service
        services[service] = regions_dict
        # Init objects for every new service
        old_service = service
        regions = {}
        regions["aws"] = {}
        regions["aws-cn"] = {}
        regions["aws-us-gov"] = {}
        regions_dict["regions"] = {}
        regions_aws = []
        regions_cn = []
        regions_gov = []

    # Include the region in their AWS partition
    if "cn-" in region:
        regions_cn.append(region)
        regions["aws-cn"] = regions_cn

    elif "gov-" in region:
        regions_gov.append(region)
        regions["aws-us-gov"] = regions_gov
    else:
        regions_aws.append(region)
        regions["aws"] = regions_aws

    regions_dict["regions"] = regions

# Store final JSON
logging.info("Storing final JSON")
regions_by_service["services"] = services

# Include the regions for the subservices and the services not present
# accessanalyzer --> iam
regions_by_service["services"]["accessanalyzer"] = regions_by_service["services"]["iam"]
# apigatewayv2 --> apigateway
regions_by_service["services"]["apigatewayv2"] = regions_by_service["services"][
    "apigateway"
]
# macie2 --> macie
regions_by_service["services"]["macie2"] = regions_by_service["services"]["macie"]
# logs --> cloudwatch
regions_by_service["services"]["logs"] = regions_by_service["services"]["cloudwatch"]
# dax --> dynamodb
regions_by_service["services"]["dax"] = regions_by_service["services"]["dynamodb"]
# glacier --> s3
regions_by_service["services"]["glacier"] = regions_by_service["services"]["s3"]
# opensearch --> es
regions_by_service["services"]["opensearch"] = regions_by_service["services"]["es"]
# elbv2 --> elb
regions_by_service["services"]["elbv2"] = regions_by_service["services"]["elb"]
# route53domains --> route53
regions_by_service["services"]["route53domains"] = regions_by_service["services"][
    "route53"
]
# s3control --> s3
regions_by_service["services"]["s3control"] = regions_by_service["services"]["s3"]
# wafv2 --> waf
regions_by_service["services"]["wafv2"] = regions_by_service["services"]["waf"]
# waf-regional --> waf
regions_by_service["services"]["waf-regional"] = regions_by_service["services"]["waf"]

# Write to file
logging.info(f"Writing {parsed_matrix_regions_aws}")
with open(parsed_matrix_regions_aws, "w") as outfile:
    json.dump(regions_by_service, outfile, indent=2, sort_keys=True)
