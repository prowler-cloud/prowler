from typing import Optional

from prowler.lib.check.models import CheckReportM365
from prowler.lib.logger import logger
from prowler.providers.m365.lib.fix.fixer import M365Fixer
from prowler.providers.m365.services.purview.purview_client import purview_client


class PurviewAuditLogSearchEnabledFixer(M365Fixer):
    """
    Fixer for Purview audit log search.
    This fixer enables the audit log search using PowerShell.
    """

    def __init__(self):
        """
        Initialize Purview audit log search fixer.
        """
        super().__init__(
            description="Enable Purview audit log search",
            cost_impact=False,
            cost_description=None,
            service="purview",
        )

    def fix(self, finding: Optional[CheckReportM365] = None, **kwargs) -> bool:
        """
        Enable Purview audit log search using PowerShell.
        This fixer executes the Set-AdminAuditLogConfig cmdlet to enable the audit log search.

        Args:
            finding (Optional[CheckReportM365]): Finding to fix
            **kwargs: Additional arguments

        Returns:
            bool: True if the operation is successful (audit log search is enabled), False otherwise
        """
        try:
            super().fix()

            purview_client.powershell.set_audit_log_config()
            purview_client.powershell.close()
            return True
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            purview_client.powershell.close()
            return False
