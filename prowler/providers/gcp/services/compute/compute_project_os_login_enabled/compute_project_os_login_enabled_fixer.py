from typing import Optional

from prowler.lib.check.models import Check_Report_GCP
from prowler.lib.logger import logger
from prowler.providers.gcp.lib.fix.fixer import GCPFixer
from prowler.providers.gcp.services.compute.compute_client import compute_client


class ComputeProjectOSLoginEnabledFixer(GCPFixer):
    """
    Fixer for enabling OS Login at the project level.
    This fixer enables the OS Login feature which provides centralized and automated SSH key pair management.
    """

    def __init__(self):
        """
        Initialize Compute Engine fixer.
        """
        super().__init__(
            description="Enable OS Login at the project level",
            cost_impact=False,
            cost_description=None,
            service="compute",
            iam_policy_required={
                "roles": ["roles/compute.admin"],
            },
        )

    def fix(self, finding: Optional[Check_Report_GCP] = None, **kwargs) -> bool:
        """
        Enable OS Login at the project level.

        Args:
            finding (Optional[Check_Report_GCP]): Finding to fix
            **kwargs: Additional arguments (project_id is required if finding is not provided)

        Returns:
            bool: True if the operation is successful (OS Login is enabled), False otherwise
        """
        try:
            # Get project_id either from finding or kwargs
            if finding:
                project_id = finding.project_id
            else:
                project_id = kwargs.get("project_id")

            if not project_id:
                raise ValueError("project_id is required")

            # Enable OS Login
            request = compute_client.client.projects().setCommonInstanceMetadata(
                project=project_id,
                body={"items": [{"key": "enable-oslogin", "value": "TRUE"}]},
            )
            request.execute()

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
