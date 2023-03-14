import sys

from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import generate_regional_clients
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info


def get_tagged_resources(input_resource_tags: list, current_audit_info: AWS_Audit_Info):
    """
    get_tagged_resources returns a list of the resources that are going to be scanned based on the given input tags
    """
    try:
        resource_tags = []
        tagged_resources = []
        for tag in input_resource_tags:
            key = tag.split("=")[0]
            value = tag.split("=")[1]
            resource_tags.append({"Key": key, "Values": [value]})
        # Get Resources with resource_tags for all regions
        for regional_client in generate_regional_clients(
            "resourcegroupstaggingapi", current_audit_info
        ).values():
            try:
                get_resources_paginator = regional_client.get_paginator("get_resources")
                for page in get_resources_paginator.paginate(TagFilters=resource_tags):
                    for resource in page["ResourceTagMappingList"]:
                        tagged_resources.append(resource["ResourceARN"])
            except Exception as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)
    else:
        return tagged_resources
