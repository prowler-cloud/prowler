from typing import Optional

from botocore.client import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class SecurityHub(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.securityhubs = []
        self.organization_admin_accounts = []
        self.__threading_call__(self._describe_hub)
        self.__threading_call__(self._list_tags, self.securityhubs)
        self.__threading_call__(self._list_organization_admin_accounts)
        self.__threading_call__(
            self._describe_organization_configuration, self.securityhubs
        )

    def _describe_hub(self, regional_client):
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
                            arn=self.get_unknown_arn(
                                region=regional_client.region, resource_type="hub"
                            ),
                            id="hub/unknown",
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
                            arn=self.get_unknown_arn(
                                region=regional_client.region, resource_type="hub"
                            ),
                            id="hub/unknown",
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

    def _list_tags(self, resource: any):
        try:
            if resource.status != "NOT_AVAILABLE":
                resource.tags = [
                    self.regional_clients[resource.region].list_tags_for_resource(
                        ResourceArn=resource.arn
                    )["Tags"]
                ]
        except Exception as error:
            logger.error(
                f"{resource.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_organization_admin_accounts(self, regional_client):
        """List Security Hub delegated administrator accounts for the organization.

        This API is only available to the organization management account or
        a delegated administrator account.
        """
        logger.info("SecurityHub - listing organization admin accounts...")
        try:
            paginator = regional_client.get_paginator(
                "list_organization_admin_accounts"
            )
            for page in paginator.paginate():
                for admin in page.get("AdminAccounts", []):
                    admin_account = OrganizationAdminAccount(
                        admin_account_id=admin.get("AdminAccountId"),
                        admin_status=admin.get("AdminStatus"),
                        region=regional_client.region,
                    )
                    # Avoid duplicates across regions for the same admin account
                    if not any(
                        existing.admin_account_id == admin_account.admin_account_id
                        and existing.region == admin_account.region
                        for existing in self.organization_admin_accounts
                    ):
                        self.organization_admin_accounts.append(admin_account)
        except ClientError as error:
            if error.response["Error"]["Code"] in (
                "AccessDeniedException",
                "InvalidAccessException",
                "BadRequestException",
            ):
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_organization_configuration(self, securityhub):
        """Describe the organization configuration for a Security Hub instance.

        This provides information about auto-enable settings for the organization.
        Only invoked for hubs in ACTIVE status.
        """
        logger.info("SecurityHub - describing organization configuration...")
        try:
            if securityhub.status != "ACTIVE":
                return
            regional_client = self.regional_clients[securityhub.region]
            org_config = regional_client.describe_organization_configuration()
            securityhub.organization_auto_enable = org_config.get("AutoEnable", False)
            securityhub.auto_enable_standards = org_config.get(
                "AutoEnableStandards", "NONE"
            )
            securityhub.organization_config_available = True
        except ClientError as error:
            if error.response["Error"]["Code"] in (
                "AccessDeniedException",
                "InvalidAccessException",
                "BadRequestException",
            ):
                # Expected when not running from management or delegated admin account
                logger.warning(
                    f"{securityhub.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{securityhub.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{securityhub.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class OrganizationAdminAccount(BaseModel):
    """Represents a Security Hub delegated administrator account."""

    admin_account_id: str
    admin_status: str  # ENABLED or DISABLE_IN_PROGRESS
    region: str


class SecurityHubHub(BaseModel):
    arn: str
    id: str
    status: str
    standards: str
    integrations: str
    region: str
    tags: Optional[list] = []
    # Organization configuration fields
    organization_auto_enable: bool = False
    auto_enable_standards: str = "NONE"
    organization_config_available: bool = False
