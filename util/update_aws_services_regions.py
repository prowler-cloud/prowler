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
parsed__matrix_regions_aws = f"{os.path.dirname(os.path.realpath(__name__))}/providers/aws/aws_regions_by_service.json"

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
        regions["cn"] = {}
        regions["gov"] = {}
        regions_dict["regions"] = {}
        regions_aws = []
        regions_cn = []
        regions_gov = []

    # Include the region in their AWS partition
    if "cn-" in region:
        regions_cn.append(region)
        regions["cn"] = regions_cn

    elif "gov-" in region:
        regions_gov.append(region)
        regions["gov"] = regions_gov
    else:
        regions_aws.append(region)
        regions["aws"] = regions_aws

    regions_dict["regions"] = regions

# Store final JSON
logging.info(f"Storing final JSON")
regions_by_service["services"] = services

# Write to file
logging.info(f"Writing {parsed__matrix_regions_aws}")
with open(parsed__matrix_regions_aws, "w") as outfile:
    json.dump(regions_by_service, outfile, indent=2)
