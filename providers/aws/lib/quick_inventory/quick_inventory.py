from alive_progress import alive_bar
from colorama import Fore, Style

from config.config import orange_color, output_file_timestamp
from lib.logger import logger
from providers.aws.lib.audit_info.models import AWS_Audit_Info


def quick_inventory(audit_info: AWS_Audit_Info, output_directory: str):
    print(
        f"Running Quick Inventory for AWS Account {Fore.YELLOW}{audit_info.audited_account}{Style.RESET_ALL}...\n"
    )
    resources = []
    f"{output_directory}/prowler-inventory-{audit_info.audited_account}-{output_file_timestamp}.csv"

    # If not inputed regions, check all of them
    if not audit_info.audited_regions:
        # EC2 client for describing all regions
        ec2_client = audit_info.audit_session.client("ec2")
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
            bar.title = f"\n-> Scanning {orange_color}{region}{Style.RESET_ALL} region"
            resources_in_region = []
            try:
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
                    f"Found {Fore.GREEN}{len(resources_in_region)}{Style.RESET_ALL} resources in region {Fore.YELLOW}{region}{Style.RESET_ALL}\n\n"
                )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                bar()

            resources.extend(resources_in_region)
        bar.title = f"-> {Fore.GREEN}Quick Inventory is completed!{Style.RESET_ALL}"
