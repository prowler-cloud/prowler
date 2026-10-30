import json
import logging
import os
import sys

import boto3
from botocore.session import Session as BotocoreSession

# Logging config
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
    level=logging.INFO,
)

# AWS partitions that the SSM global-infrastructure parameters do not publish.
# Their availability comes from the endpoints.json bundled with botocore, which
# is offline data and needs neither credentials nor network access.
ISO_PARTITIONS = ("aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f")

# Cost Explorer: botocore keys it by its endpoint prefix "ce", while the matrix
# (and the boto3 client name) calls it "costexplorer". Explicit rename override,
# since no boto3 service model resolves the "ce" prefix.
ISO_ENDPOINT_PREFIX_RENAMES = {"ce": "costexplorer"}

# "transcribestreaming" is the streaming endpoint of Amazon Transcribe. The
# "transcribe" prefix is already present in the same partitions with the same
# regions, so mapping it would only duplicate data. Ignoring it is a deliberate
# decision, not a resolution failure.
ISO_IGNORED_ENDPOINT_PREFIXES = {"transcribestreaming"}

# A service whose only endpoint in a partition is the partition-wide pseudo
# endpoint (for example "aws-iso-global") gets every region of that partition,
# matching how the matrix already records iam, organizations, route53 and
# support for aws and aws-us-gov. Cost Explorer is the exception: the matrix
# records it as a single-region service (aws: us-east-1, aws-cn: cn-northwest-1),
# so it only gets the region declared in the endpoint's credentialScope.
ISO_SINGLE_REGION_PARTITION_GLOBAL_SERVICES = {"costexplorer"}


def get_regions_by_service_from_ssm() -> dict:
    """Get the AWS services and their regions for the partitions published in
    the SSM global-infrastructure parameters: aws, aws-cn, aws-eusc and
    aws-us-gov.

    Returns:
        dict: The AWS regions matrix, keyed by service name.
    """
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
            regions = {
                "aws": [],
                "aws-cn": [],
                "aws-eusc": [],
                "aws-us-gov": [],
                "aws-iso": [],
                "aws-iso-b": [],
                "aws-iso-e": [],
                "aws-iso-f": [],
            }
            for page in get_parameters_by_path_paginator.paginate(
                Path="/aws/service/global-infrastructure/services/"
                + service["Value"]
                + "/regions"
            ):
                for region in page["Parameters"]:
                    if "cn" in region["Value"]:
                        regions["aws-cn"].append(region["Value"])
                    elif "eusc" in region["Value"]:
                        regions["aws-eusc"].append(region["Value"])
                    elif "gov" in region["Value"]:
                        regions["aws-us-gov"].append(region["Value"])
                    else:
                        regions["aws"].append(region["Value"])
                    # Sort regions per partition
                    regions["aws"] = sorted(regions["aws"])
                    regions["aws-cn"] = sorted(regions["aws-cn"])
                    regions["aws-eusc"] = sorted(regions["aws-eusc"])
                    regions["aws-us-gov"] = sorted(regions["aws-us-gov"])
            regions_by_service["services"][service["Value"]]["regions"] = regions

    return regions_by_service


def add_subservices_and_missing_services(regions_by_service: dict) -> None:
    """Include the regions for the subservices and the services not present in
    the original matrix."""
    logging.info(
        "Updating subservices and the services not present in the original matrix"
    )
    # macie2 --> macie
    regions_by_service["services"]["macie2"] = regions_by_service["services"]["macie"]
    # bedrock-agent is not in SSM, and has different availability than bedrock
    # See: https://docs.aws.amazon.com/bedrock/latest/userguide/agents-supported.html
    regions_by_service["services"]["bedrock-agent"] = {
        "regions": {
            "aws": [
                "ap-northeast-1",
                "ap-northeast-2",
                "ap-south-1",
                "ap-southeast-1",
                "ap-southeast-2",
                "ca-central-1",
                "eu-central-1",
                "eu-central-2",
                "eu-west-1",
                "eu-west-2",
                "eu-west-3",
                "sa-east-1",
                "us-east-1",
                "us-west-2",
            ],
            "aws-cn": [],
            "aws-eusc": [],
            "aws-us-gov": [
                "us-gov-west-1",
            ],
        }
    }
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
    # sesv2 --> ses
    regions_by_service["services"]["sesv2"] = regions_by_service["services"]["ses"]
    # bedrock-agentcore-control is the control-plane client name. SSM global
    # infrastructure only returns bedrock-agentcore, so alias it or the key
    # disappears on the next region refresh.
    if "bedrock-agentcore" in regions_by_service["services"]:
        regions_by_service["services"]["bedrock-agentcore-control"] = (
            regions_by_service["services"]["bedrock-agentcore"]
        )


def get_endpoint_prefix_to_services() -> dict:
    """Map every botocore endpoint prefix to the set of boto3 service (client)
    names using it.

    botocore's endpoints.json keys services by endpoint prefix, while the matrix
    keys them by the boto3/SSM service name. The mapping is derived from the SDK
    itself instead of being hand-written, so it stays correct as the SDK evolves
    (monitoring -> cloudwatch, elasticloadbalancing -> elb and elbv2, states ->
    stepfunctions, api.ecr -> ecr, ...).

    Returns:
        dict: A dictionary mapping each endpoint prefix to a set of service names.
    """
    session = BotocoreSession()
    endpoint_prefix_to_services = {}
    for service_name in session.get_available_services():
        endpoint_prefix = session.get_service_model(service_name).endpoint_prefix
        endpoint_prefix_to_services.setdefault(endpoint_prefix, set()).add(service_name)
    return endpoint_prefix_to_services


def resolve_matrix_services(
    endpoint_prefix: str, endpoint_prefix_to_services: dict, services: dict
) -> set:
    """Resolve a botocore endpoint prefix to the matrix service names it stands
    for.

    Args:
        - endpoint_prefix: The botocore endpoint prefix.
        - endpoint_prefix_to_services: The map returned by get_endpoint_prefix_to_services.
        - services: The services of the AWS regions matrix.

    Returns:
        set: The matrix service names, empty when the prefix does not resolve.
    """
    renamed_service = ISO_ENDPOINT_PREFIX_RENAMES.get(endpoint_prefix)
    if renamed_service:
        return {renamed_service} & set(services)

    service_names = endpoint_prefix_to_services.get(endpoint_prefix, set()) & set(
        services
    )
    if not service_names and endpoint_prefix in services:
        service_names = {endpoint_prefix}
    return service_names


def get_partition_global_service_regions(
    service_names: set, service_data: dict, partition_regions: list
) -> list:
    """Get the regions of a service whose only endpoint in the partition is the
    partition-wide pseudo endpoint (for example "aws-iso-global"), which is not
    a region and must never be recorded as one.

    Returns:
        list: Every region of the partition, or only the credentialScope region
            for the services the matrix records as single-region ones.
    """
    partition_endpoint = service_data.get("partitionEndpoint")
    credential_scope_region = (
        service_data.get("endpoints", {})
        .get(partition_endpoint, {})
        .get("credentialScope", {})
        .get("region")
    )
    if service_names & ISO_SINGLE_REGION_PARTITION_GLOBAL_SERVICES:
        if credential_scope_region in partition_regions:
            return [credential_scope_region]
        return []
    return list(partition_regions)


def add_iso_partitions_regions(regions_by_service: dict) -> None:
    """Fill the aws-iso, aws-iso-b, aws-iso-e and aws-iso-f regions of every
    service from the endpoints.json bundled with botocore.

    It runs after the subservices and the services not present in the original
    matrix have been added, so it sees the final set of services: the aliases
    sharing a single dict and the hand-written bedrock-agent entry all get their
    ISO partition keys.

    Raises:
        ValueError: If an endpoint prefix present in an ISO partition does not
            resolve to a matrix service and is not explicitly ignored.
    """
    logging.info("Updating the ISO partitions regions from the botocore endpoints")
    services = regions_by_service["services"]
    endpoints_data = BotocoreSession().get_data("endpoints")
    endpoint_prefix_to_services = get_endpoint_prefix_to_services()

    # Every service carries every partition key, so the matrix stays rectangular
    # even for the services with no presence at all in the ISO partitions.
    for service in services.values():
        for partition in ISO_PARTITIONS:
            service["regions"].setdefault(partition, [])

    for partition_data in endpoints_data["partitions"]:
        partition = partition_data["partition"]
        if partition not in ISO_PARTITIONS:
            continue
        partition_regions = sorted(partition_data.get("regions", {}))
        for endpoint_prefix, service_data in partition_data.get("services", {}).items():
            if endpoint_prefix in ISO_IGNORED_ENDPOINT_PREFIXES:
                continue
            service_names = resolve_matrix_services(
                endpoint_prefix, endpoint_prefix_to_services, services
            )
            if not service_names:
                raise ValueError(
                    f"The botocore endpoint prefix '{endpoint_prefix}', present in the "
                    f"'{partition}' partition, does not resolve to any service of the "
                    "AWS regions matrix. Dropping it silently would leave the service "
                    "out of the scans, so either add the prefix to "
                    "ISO_ENDPOINT_PREFIX_RENAMES with the matrix service name it "
                    "corresponds to, or add it to ISO_IGNORED_ENDPOINT_PREFIXES if it "
                    "must not be mapped."
                )
            # Keep only the endpoints that are real regions of the partition,
            # which drops the fips-* and the partition-wide pseudo endpoints.
            regions = sorted(
                set(service_data.get("endpoints", {})) & set(partition_regions)
            )
            if not regions:
                regions = get_partition_global_service_regions(
                    service_names, service_data, partition_regions
                )
            for service_name in service_names:
                services[service_name]["regions"][partition] = list(regions)


def write_regions_by_service(regions_by_service: dict) -> None:
    """Write the AWS regions matrix to the file read by the AWS provider."""
    repository_root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    parsed_matrix_regions_aws = (
        f"{repository_root}/prowler/providers/aws/aws_regions_by_service.json"
    )
    logging.info(f"Writing {parsed_matrix_regions_aws}")
    with open(parsed_matrix_regions_aws, "w") as outfile:
        json.dump(regions_by_service, outfile, indent=2, sort_keys=True)
        outfile.write("\n")


def main() -> None:
    regions_by_service = get_regions_by_service_from_ssm()
    add_subservices_and_missing_services(regions_by_service)
    add_iso_partitions_regions(regions_by_service)
    write_regions_by_service(regions_by_service)


if __name__ == "__main__":
    main()
