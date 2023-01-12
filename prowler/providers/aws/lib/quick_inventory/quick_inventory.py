import csv
import json

from alive_progress import alive_bar
from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import (
    csv_file_suffix,
    json_file_suffix,
    orange_color,
    output_file_timestamp,
)
from prowler.lib.logger import logger
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info


def quick_inventory(audit_info: AWS_Audit_Info, output_directory: str):
    print(
        f"-=- Running Quick Inventory for AWS Account {Fore.YELLOW}{audit_info.audited_account}{Style.RESET_ALL} -=-\n"
    )
    resources = []
    # If not inputed regions, check all of them
    if not audit_info.audited_regions:
        # EC2 client for describing all regions
        ec2_client = audit_info.audit_session.client(
            "ec2", region_name=audit_info.profile_region
        )
        # Get all the available regions
        audit_info.audited_regions = [
            region["RegionName"] for region in ec2_client.describe_regions()["Regions"]
        ]

    with alive_bar(
        total=len(audit_info.audited_regions),
        ctrl_c=False,
        bar="blocks",
        spinner="classic",
        stats=False,
        enrich_print=False,
    ) as bar:
        for region in sorted(audit_info.audited_regions):
            bar.title = f"-> Scanning {orange_color}{region}{Style.RESET_ALL} region"
            resources_in_region = []
            try:
                # If us-east-1 get IAM resources from there otherwise see if it is US GovCloud or China
                iam_client = audit_info.audit_session.client("iam")
                if (
                    region == "us-east-1"
                    or region == "us-gov-west-1"
                    or region == "cn-north-1"
                ):

                    get_roles_paginator = iam_client.get_paginator("list_roles")
                    for page in get_roles_paginator.paginate():
                        for role in page["Roles"]:
                            # Avoid aws-service-role roles
                            if "aws-service-role" not in role["Arn"]:
                                resources_in_region.append(role["Arn"])

                    get_users_paginator = iam_client.get_paginator("list_users")
                    for page in get_users_paginator.paginate():
                        for user in page["Users"]:
                            resources_in_region.append(user["Arn"])

                    get_groups_paginator = iam_client.get_paginator("list_groups")
                    for page in get_groups_paginator.paginate():
                        for group in page["Groups"]:
                            resources_in_region.append(group["Arn"])

                    get_policies_paginator = iam_client.get_paginator("list_policies")
                    for page in get_policies_paginator.paginate(Scope="Local"):
                        for policy in page["Policies"]:
                            resources_in_region.append(policy["Arn"])

                    for saml_provider in iam_client.list_saml_providers()[
                        "SAMLProviderList"
                    ]:
                        resources_in_region.append(saml_provider["Arn"])

                client = audit_info.audit_session.client(
                    "resourcegroupstaggingapi", region_name=region
                )
                # Get all the resources
                resources_count = 0
                get_resources_paginator = client.get_paginator("get_resources")
                for page in get_resources_paginator.paginate():
                    resources_count += len(page["ResourceTagMappingList"])
                    for resource in page["ResourceTagMappingList"]:
                        resources_in_region.append(resource["ResourceARN"])
                bar()
                print(
                    f"Found {Fore.GREEN}{len(resources_in_region)}{Style.RESET_ALL} resources in region {Fore.YELLOW}{region}{Style.RESET_ALL}"
                )
                print("\n")

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                bar()

            resources.extend(resources_in_region)
        bar.title = f"-> {Fore.GREEN}Quick Inventory completed!{Style.RESET_ALL}"

    inventory_table = create_inventory_table(resources)

    print(
        f"\nQuick Inventory of AWS Account {Fore.YELLOW}{audit_info.audited_account}{Style.RESET_ALL}:"
    )

    print(tabulate(inventory_table, headers="keys", tablefmt="rounded_grid"))

    print(f"\nTotal resources found: {Fore.GREEN}{len(resources)}{Style.RESET_ALL}")

    create_output(resources, audit_info, output_directory)


def create_inventory_table(resources: list) -> dict:

    services = {}
    # { "S3":
    #       123,
    #   "IAM":
    #       239,
    # }
    resources_type = {}
    # { "S3":
    #       "Buckets": 13,
    #   "IAM":
    #       "Roles": 143,
    #       "Users": 22,
    # }
    for resource in sorted(resources):
        service = resource.split(":")[2]
        if service not in services:
            services[service] = 0
        services[service] += 1

        if service == "s3":
            resource_type = "bucket"
        else:
            resource_type = resource.split(":")[5].split("/")[0]
        if service not in resources_type:
            resources_type[service] = {}
        if resource_type not in resources_type[service]:
            resources_type[service][resource_type] = 0
        resources_type[service][resource_type] += 1

    # Add results to inventory table
    inventory_table = {
        "Service": [],
        "Total": [],
        "Count per resource types": [],
    }
    for service in services:
        summary = ""
        inventory_table["Service"].append(f"{service}")
        inventory_table["Total"].append(
            f"{Fore.GREEN}{services[service]}{Style.RESET_ALL}"
        )
        for resource_type in resources_type[service]:
            summary += f"{resource_type} {Fore.GREEN}{resources_type[service][resource_type]}{Style.RESET_ALL}\n"
        inventory_table["Count per resource types"].append(summary)

    return inventory_table


def create_output(resources: list, audit_info: AWS_Audit_Info, output_directory: str):

    json_output = []
    output_file = f"{output_directory}/prowler-inventory-{audit_info.audited_account}-{output_file_timestamp}"

    for item in sorted(resources):
        resource = {}
        resource["AWS_AccountID"] = audit_info.audited_account
        resource["AWS_Region"] = item.split(":")[3]
        resource["AWS_Partition"] = item.split(":")[1]
        resource["AWS_Service"] = item.split(":")[2]
        resource["AWS_ResourceType"] = item.split(":")[5].split("/")[0]
        resource["AWS_ResourceID"] = ""
        if len(item.split("/")) > 1:
            resource["AWS_ResourceID"] = item.split("/")[-1]
        elif len(item.split(":")) > 6:
            resource["AWS_ResourceID"] = item.split(":")[-1]
        resource["AWS_ResourceARN"] = item
        # Cover S3 case
        if resource["AWS_Service"] == "s3":
            resource["AWS_ResourceType"] = "bucket"
            resource["AWS_ResourceID"] = item.split(":")[-1]
        # Cover WAFv2 case
        if resource["AWS_Service"] == "wafv2":
            resource["AWS_ResourceType"] = "/".join(item.split(":")[-1].split("/")[:-2])
            resource["AWS_ResourceID"] = "/".join(item.split(":")[-1].split("/")[2:])
        # Cover Config case
        if resource["AWS_Service"] == "config":
            resource["AWS_ResourceID"] = "/".join(item.split(":")[-1].split("/")[1:])
        json_output.append(resource)

    # Serializing json
    json_object = json.dumps(json_output, indent=4)

    # Writing to sample.json
    with open(output_file + json_file_suffix, "w") as outfile:
        outfile.write(json_object)

    csv_file = open(output_file + csv_file_suffix, "w", newline="")
    csv_writer = csv.writer(csv_file)

    count = 0
    for data in json_output:
        if count == 0:
            header = data.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(data.values())

    csv_file.close()

    print("\nMore details in files:")
    print(f" - CSV: {output_file+csv_file_suffix}")
    print(f" - JSON: {output_file+json_file_suffix}")
