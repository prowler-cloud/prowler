from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWS_Service


################## SecurityHub
class SecurityHub(AWS_Service):
    def __init__(self, audit_info):
        # Call AWS_Service's __init__
        super().__init__(__class__.__name__, audit_info)
        self.securityhubs = []
        self.__threading_call__(self.__describe_hub__)

    def __describe_hub__(self, regional_client):
        logger.info("SecurityHub - Describing Hub...")
        try:
            # Check if SecurityHub is active
            try:
                hub_arn = regional_client.describe_hub()["HubArn"]
            except ClientError as e:
                # Check if Account is subscribed to Security Hub
                if e.response["Error"]["Code"] == "InvalidAccessException":
                    self.securityhubs.append(
                        SecurityHubHub(
                            arn="",
                            id="Security Hub",
                            status="NOT_AVAILABLE",
                            standards="",
                            integrations="",
                            region=regional_client.region,
                        )
                    )
            else:
                if not self.audit_resources or (
                    is_resource_filtered(hub_arn, self.audit_resources)
                ):
                    hub_id = hub_arn.split("/")[1]
                    get_enabled_standards_paginator = regional_client.get_paginator(
                        "get_enabled_standards"
                    )
                    standards = ""
                    for page in get_enabled_standards_paginator.paginate():
                        for standard in page["StandardsSubscriptions"]:
                            standards += f"{standard['StandardsArn'].split('/')[1]} "
                    list_enabled_products_for_import_paginator = (
                        regional_client.get_paginator(
                            "list_enabled_products_for_import"
                        )
                    )
                    integrations = ""
                    for page in list_enabled_products_for_import_paginator.paginate():
                        for integration in page["ProductSubscriptions"]:
                            if (
                                "/aws/securityhub" not in integration
                            ):  # ignore Security Hub integration with itself
                                integrations += f"{integration.split('/')[-1]} "
                    self.securityhubs.append(
                        SecurityHubHub(
                            arn=hub_arn,
                            id=hub_id,
                            status="ACTIVE",
                            standards=standards,
                            integrations=integrations,
                            region=regional_client.region,
                        )
                    )
                else:
                    # SecurityHub is filtered
                    self.securityhubs.append(
                        SecurityHubHub(
                            arn="",
                            id="Security Hub",
                            status="NOT_AVAILABLE",
                            standards="",
                            integrations="",
                            region=regional_client.region,
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class SecurityHubHub(BaseModel):
    arn: str
    id: str
    status: str
    standards: str
    integrations: str
    region: str
