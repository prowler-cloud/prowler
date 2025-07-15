from typing import Dict, Optional

from prowler.lib.check.models import Check_Report_GCP
from prowler.lib.fix.fixer import Fixer
from prowler.lib.logger import logger
from prowler.providers.gcp.gcp_provider import GcpProvider


class GCPFixer(Fixer):
    """GCP specific fixer implementation"""

    def __init__(
        self,
        description: str,
        cost_impact: bool = False,
        cost_description: Optional[str] = None,
        service: str = "",
        iam_policy_required: Optional[Dict] = None,
    ):
        """
        Initialize GCP fixer with metadata.

        Args:
            description (str): Description of the fixer
            cost_impact (bool): Whether the fixer has a cost impact
            cost_description (Optional[str]): Description of the cost impact
            service (str): GCP service name
            iam_policy_required (Optional[Dict]): Required IAM policy for the fixer
        """
        super().__init__(description, cost_impact, cost_description)
        self.service = service
        self.iam_policy_required = iam_policy_required or {}
        self._provider = None

    @property
    def provider(self) -> GcpProvider:
        """Get the GCP provider instance"""
        if not self._provider:
            self._provider = GcpProvider()
        return self._provider

    def _get_fixer_info(self) -> Dict:
        """Get fixer metadata"""
        info = super()._get_fixer_info()
        info["service"] = self.service
        info["iam_policy_required"] = self.iam_policy_required
        info["provider"] = "gcp"
        return info

    def fix(self, finding: Optional[Check_Report_GCP] = None, **kwargs) -> bool:
        """
        GCP specific method to execute the fixer.
        This method handles the printing of fixing status messages.

        Args:
            finding (Optional[Check_Report_GCP]): Finding to fix
            **kwargs: Additional GCP-specific arguments (project_id, resource_id)

        Returns:
            bool: True if fixing was successful, False otherwise
        """
        try:
            # Get values either from finding or kwargs
            project_id = None
            resource_id = None

            if finding:
                project_id = (
                    finding.project_id if hasattr(finding, "project_id") else None
                )
                resource_id = (
                    finding.resource_id if hasattr(finding, "resource_id") else None
                )
            else:
                project_id = kwargs.get("project_id")
                resource_id = kwargs.get("resource_id")

            # Print the appropriate message based on available information
            if project_id and resource_id:
                print(f"\tFIXING {resource_id} in project {project_id}...")
            elif project_id:
                print(f"\tFIXING project {project_id}...")
            elif resource_id:
                print(f"\tFIXING Resource {resource_id}...")
            else:
                logger.error(
                    "Either finding or required kwargs (project_id, resource_id) must be provided"
                )
                return False

            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
