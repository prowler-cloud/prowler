from typing import Optional

from azure.mgmt.web.models import SiteConfigResource

from prowler.lib.check.models import Check_Report_Azure
from prowler.providers.azure.lib.fix.fixer import AzureFixer
from prowler.providers.azure.services.app.app_client import app_client


class AppFunctionFtpsDeploymentDisabledFixer(AzureFixer):
    """
    This class handles the remediation of the app_function_ftps_deployment_disabled check.
    It disables FTP/FTPS deployments for Azure Functions to prevent unauthorized access.
    """

    def __init__(self):
        super().__init__(
            description="Disable FTP/FTPS deployments for Azure Functions",
            service="app",
            cost_impact=False,
            cost_description=None,
        )

    def fix(self, finding: Optional[Check_Report_Azure] = None, **kwargs) -> bool:
        """
        Fix the failed check by disabling FTP/FTPS deployments for the Azure Function.

        Args:
            finding (Check_Report_Azure): Finding to fix
            **kwargs: Additional Azure-specific arguments (subscription_id, resource_id, resource_group)

        Returns:
            bool: True if FTP/FTPS is disabled, False otherwise
        """
        try:
            # First call parent fix method to handle common Azure fix operations
            if not super().fix(finding, **kwargs):
                return False

            # Get values either from finding or kwargs
            if finding:
                resource_group = finding.resource.get("resource_group_name")
                app_name = finding.resource_name
                suscription_name = finding.subscription
            else:
                resource_group = kwargs.get("resource_group")
                app_name = kwargs.get("resource_id")
                suscription_name = kwargs.get("subscription_id")

            if not resource_group or not app_name or not suscription_name:
                raise ValueError(
                    "Resource group, app name and subscription name are required"
                )

            # Get the Azure client for this subscription
            client = app_client.clients[suscription_name]

            # Create the SiteConfigResource object
            site_config = SiteConfigResource(ftps_state="Disabled")

            # Update the function configuration to disable FTP/FTPS
            client.web_apps.update_configuration(
                resource_group_name=resource_group,
                name=app_name,
                site_config=site_config,
            )

            return True

        except Exception as error:
            self.logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
