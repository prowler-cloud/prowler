import csv
import json
from copy import deepcopy

from alive_progress import alive_bar
from botocore.client import ClientError
from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import (
    csv_file_suffix,
    json_file_suffix,
    orange_color,
    output_file_timestamp,
)
from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.arn.models import get_arn_resource_type


def quick_inventory(provider: AwsProvider, args):
    try:
        resources = []
        global_resources = []
        total_resources_per_region = {}
        iam_was_scanned = False
        # If not inputed regions, check all of them
        if not provider.identity.audited_regions:
            # EC2 client for describing all regions
            ec2_client = provider.session.current_session.client(
                "ec2", region_name=provider.identity.profile_region
            )
            # Get all the available regions
            provider.identity.audited_regions = [
                region["RegionName"]
                for region in ec2_client.describe_regions()["Regions"]
            ]

        with alive_bar(
            total=len(provider.identity.audited_regions),
            ctrl_c=False,
            bar="blocks",
            spinner="classic",
            stats=False,
            enrich_print=False,
        ) as bar:
            for region in sorted(provider.identity.audited_regions):
                bar.title = f"Inventorying AWS Account {orange_color}{provider.identity.account}{Style.RESET_ALL}"
                resources_in_region = []
                # {
                #   eu-west-1: 100,...
                # }

                try:
                    # Scan IAM only once
                    if not iam_was_scanned:
                        global_resources.extend(
                            get_iam_resources(provider.session.current_session)
                        )
                        iam_was_scanned = True

                    # Get regional S3 buckets since none-tagged buckets are not supported by the resourcegroupstaggingapi
                    resources_in_region.extend(get_regional_buckets(provider, region))

                    client = provider.session.current_session.client(
                        "resourcegroupstaggingapi", region_name=region
                    )
                    # Get all the resources
                    resources_count = 0
                    try:
                        get_resources_paginator = client.get_paginator("get_resources")
                        for page in get_resources_paginator.paginate():
                            resources_count += len(page["ResourceTagMappingList"])
                            for resource in page["ResourceTagMappingList"]:
                                # Avoid adding S3 buckets again:
                                if resource["ResourceARN"].split(":")[2] != "s3":
                                    # Check if region is not in ARN --> Global service
                                    if not resource["ResourceARN"].split(":")[3]:
                                        global_resources.append(
                                            {
                                                "arn": resource["ResourceARN"],
                                                "tags": resource["Tags"],
                                            }
                                        )
                                    else:
                                        resources_in_region.append(
                                            {
                                                "arn": resource["ResourceARN"],
                                                "tags": resource["Tags"],
                                            }
                                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    bar()
                    if len(resources_in_region) > 0:
                        total_resources_per_region[region] = len(resources_in_region)
                    bar.text = f"-> Found {Fore.GREEN}{len(resources_in_region)}{Style.RESET_ALL} resources in {region}"

                except Exception as error:
                    logger.error(
                        f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    bar()

                resources.extend(resources_in_region)
            bar.title = f"-> {Fore.GREEN}Quick Inventory completed!{Style.RESET_ALL}"

        resources.extend(global_resources)
        total_resources_per_region["global"] = len(global_resources)
        inventory_table = create_inventory_table(resources, total_resources_per_region)

        print(
            f"\nQuick Inventory of AWS Account {Fore.YELLOW}{provider.identity.account}{Style.RESET_ALL}:"
        )

        print(
            tabulate(
                inventory_table,
                headers="keys",
                tablefmt="rounded_grid",
                stralign="left",
            )
        )
        print(f"\nTotal resources found: {Fore.GREEN}{len(resources)}{Style.RESET_ALL}")

        create_output(resources, provider, args)
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def create_inventory_table(resources: list, resources_in_region: dict) -> dict:
    try:
        regions_with_resources = list(resources_in_region.keys())
        services = {}
        # { "S3":
        #       123,
        #   "IAM":
        #       239,
        # }
        resources_type = {}
        # { "S3":
        #       "Buckets":
        #           eu-west-1: 10,
        #           eu-west-2: 3,
        #   "IAM":
        #       "Roles":
        #           us-east-1: 143,
        #       "Users":
        #           us-west-2: 22,
        # }

        inventory_table = {
            "Service": [],
            f"Total\n({Fore.GREEN}{str(len(resources))}{Style.RESET_ALL})": [],
            "Total per\nresource type": [],
        }

        for region, count in resources_in_region.items():
            inventory_table[
                f"{region}\n({Fore.GREEN}{str(count)}{Style.RESET_ALL})"
            ] = []

        for resource in sorted(resources, key=lambda d: d["arn"]):
            service = resource["arn"].split(":")[2]
            region = resource["arn"].split(":")[3]
            if not region:
                region = "global"
            if service not in services:
                services[service] = 0
            services[service] += 1

            resource_type = get_arn_resource_type(resource["arn"], service)

            if service not in resources_type:
                resources_type[service] = {}
            if resource_type not in resources_type[service]:
                resources_type[service][resource_type] = {}
            if region not in resources_type[service][resource_type]:
                resources_type[service][resource_type][region] = 0
            resources_type[service][resource_type][region] += 1

        # Add results to inventory table
        for service in services:
            pending_regions = deepcopy(regions_with_resources)
            aux = {}
            # {
            #  "region": summary,
            # }
            summary = ""
            inventory_table["Service"].append(f"{service}")
            inventory_table[
                f"Total\n({Fore.GREEN}{str(len(resources))}{Style.RESET_ALL})"
            ].append(f"{Fore.GREEN}{services[service]}{Style.RESET_ALL}")
            for resource_type, regions in resources_type[service].items():
                summary += f"{resource_type} {Fore.GREEN}{str(sum(regions.values()))}{Style.RESET_ALL}\n"
                # Check if region does not have resource type
                for region in pending_regions:
                    if region not in aux:
                        aux[region] = ""
                    if region not in regions:
                        aux[region] += "-\n"
                for region, count in regions.items():
                    aux[region] += f"{Fore.GREEN}{str(count)}{Style.RESET_ALL}\n"
            # Add Total per resource type
            inventory_table["Total per\nresource type"].append(summary)
            # Add Total per region
            for region, text in aux.items():
                inventory_table[
                    f"{region}\n({Fore.GREEN}{str(resources_in_region[region])}{Style.RESET_ALL})"
                ].append(text)
                if region in pending_regions:
                    pending_regions.remove(region)
            for region_without_resource in pending_regions:
                inventory_table[
                    f"{region_without_resource}\n ({Fore.GREEN}{str(resources_in_region[region_without_resource])}{Style.RESET_ALL})"
                ].append("-")

        return inventory_table
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def create_output(resources: list, provider: AwsProvider, args):
    try:
        json_output = []
        # Check if custom output filename was input, if not, set the default
        if not hasattr(args, "output_filename") or args.output_filename is None:
            output_file = (
                f"prowler-inventory-{provider.identity.account}-{output_file_timestamp}"
            )
        else:
            output_file = args.output_filename

        for item in sorted(resources, key=lambda d: d["arn"]):
            resource = {}
            resource["AWS_AccountID"] = provider.identity.account
            resource["AWS_Region"] = item["arn"].split(":")[3]
            resource["AWS_Partition"] = item["arn"].split(":")[1]
            resource["AWS_Service"] = item["arn"].split(":")[2]
            resource["AWS_ResourceType"] = item["arn"].split(":")[5].split("/")[0]
            resource["AWS_ResourceID"] = ""
            if len(item["arn"].split("/")) > 1:
                resource["AWS_ResourceID"] = item["arn"].split("/")[-1]
            elif len(item["arn"].split(":")) > 6:
                resource["AWS_ResourceID"] = item["arn"].split(":")[-1]
            resource["AWS_ResourceARN"] = item["arn"]
            # Cover S3 case
            if resource["AWS_Service"] == "s3":
                resource["AWS_ResourceType"] = "bucket"
                resource["AWS_ResourceID"] = item["arn"].split(":")[-1]
            # Cover WAFv2 case
            if resource["AWS_Service"] == "wafv2":
                resource["AWS_ResourceType"] = "/".join(
                    item["arn"].split(":")[-1].split("/")[:-2]
                )
                resource["AWS_ResourceID"] = "/".join(
                    item["arn"].split(":")[-1].split("/")[2:]
                )
            # Cover Config case
            if resource["AWS_Service"] == "config":
                resource["AWS_ResourceID"] = "/".join(
                    item["arn"].split(":")[-1].split("/")[1:]
                )
            resource["AWS_Tags"] = item["tags"]
            json_output.append(resource)

        # Serializing json
        json_object = json.dumps(json_output, indent=4)

        # Writing to sample.json
        with open(
            args.output_directory + "/" + output_file + json_file_suffix, "w"
        ) as outfile:
            outfile.write(json_object)

        csv_file = open(
            args.output_directory + "/" + output_file + csv_file_suffix, "w", newline=""
        )
        csv_writer = csv.writer(csv_file)

        count = 0
        for data in json_output:
            if count == 0:
                header = data.keys()
                csv_writer.writerow(header)
                count += 1
            csv_writer.writerow(data.values())

        csv_file.close()
        print(
            f"\n{Fore.YELLOW}WARNING: Only resources that have or have had tags will appear (except for IAM and S3).\nSee more in https://docs.prowler.cloud/en/latest/tutorials/quick-inventory/#objections{Style.RESET_ALL}"
        )
        print("\nMore details in files:")
        print(f" - CSV: {args.output_directory}/{output_file + csv_file_suffix}")
        print(f" - JSON: {args.output_directory}/{output_file + json_file_suffix}")

        # Send output to S3 if needed (-B / -D)

        if args.output_bucket or args.output_bucket_no_assume:
            # Check if -B was input
            if args.output_bucket:
                output_bucket = args.output_bucket
                bucket_session = provider.session.current_session
            # Check if -D was input
            elif args.output_bucket_no_assume:
                output_bucket = args.output_bucket_no_assume
                bucket_session = provider.session.original_session

            s3_client = bucket_session.client("s3")
            # FIXME: Use get_object_path method from S3 class when quick inventory uses S3 class
            bucket_remote_dir = args.output_directory
            if "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
                bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]
            # CSV
            s3_client.upload_file(
                f"{args.output_directory}/{output_file + csv_file_suffix}",
                output_bucket,
                f"{bucket_remote_dir}/{output_file + csv_file_suffix}",
            )
            # JSON
            s3_client.upload_file(
                f"{args.output_directory}/{output_file + json_file_suffix}",
                output_bucket,
                f"{bucket_remote_dir}/{output_file + json_file_suffix}",
            )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )


def get_regional_buckets(provider: AwsProvider, region: str) -> list:
    regional_buckets = []
    s3_client = provider.session.current_session.client("s3", region_name=region)
    try:
        buckets = s3_client.list_buckets()
        for bucket in buckets["Buckets"]:
            bucket_region = s3_client.get_bucket_location(Bucket=bucket["Name"])[
                "LocationConstraint"
            ]
            if bucket_region == "EU":  # If EU, bucket_region is eu-west-1
                bucket_region = "eu-west-1"
            if not bucket_region:  # If None, bucket_region is us-east-1
                bucket_region = "us-east-1"
            if bucket_region == region:  # Only add bucket if is in current region
                try:
                    bucket_tags = s3_client.get_bucket_tagging(Bucket=bucket["Name"])[
                        "TagSet"
                    ]
                except ClientError as error:
                    bucket_tags = []
                    if error.response["Error"]["Code"] != "NoSuchTagSet":
                        logger.error(
                            f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                bucket_arn = (
                    f"arn:{provider.identity.partition}:s3:{region}::{bucket['Name']}"
                )
                regional_buckets.append({"arn": bucket_arn, "tags": bucket_tags})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    return regional_buckets


def get_iam_resources(session) -> list:
    iam_resources = []
    iam_client = session.client("iam")
    try:
        get_roles_paginator = iam_client.get_paginator("list_roles")
        for page in get_roles_paginator.paginate():
            for role in page["Roles"]:
                # Avoid aws-service-role roles
                if "aws-service-role" not in role["Arn"]:
                    iam_resources.append({"arn": role["Arn"], "tags": role.get("Tags")})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    try:
        get_users_paginator = iam_client.get_paginator("list_users")
        for page in get_users_paginator.paginate():
            for user in page["Users"]:
                iam_resources.append({"arn": user["Arn"], "tags": user.get("Tags")})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    try:
        get_groups_paginator = iam_client.get_paginator("list_groups")
        for page in get_groups_paginator.paginate():
            for group in page["Groups"]:
                iam_resources.append({"arn": group["Arn"], "tags": []})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    try:
        get_policies_paginator = iam_client.get_paginator("list_policies")
        for page in get_policies_paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                iam_resources.append({"arn": policy["Arn"], "tags": policy.get("Tags")})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
    try:
        for saml_provider in iam_client.list_saml_providers()["SAMLProviderList"]:
            iam_resources.append({"arn": saml_provider["Arn"], "tags": []})
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return iam_resources
