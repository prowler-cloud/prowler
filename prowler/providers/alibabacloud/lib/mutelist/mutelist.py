"""
Alibaba Cloud Provider Mutelist

This module implements the mutelist functionality for suppressing findings
in Alibaba Cloud audits.
"""

from prowler.lib.mutelist.mutelist import Mutelist


class AlibabaCloudMutelist(Mutelist):
    """
    AlibabaCloudMutelist handles finding suppression for Alibaba Cloud resources

    This class extends the base Mutelist class to provide Alibaba Cloud-specific
    mutelist functionality, allowing users to suppress specific findings based on
    resource identifiers, regions, checks, or other criteria.

    Example mutelist entry:
    {
        "Accounts": ["1234567890"],
        "Checks": {
            "ecs_*": {
                "Regions": ["cn-hangzhou", "cn-shanghai"],
                "Resources": ["i-abc123", "i-def456"]
            }
        }
    }
    """

    def __init__(
        self,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        provider: str = "alibabacloud",
        identity: dict = None,
    ):
        """
        Initialize Alibaba Cloud mutelist

        Args:
            mutelist_path: Path to the mutelist file (YAML or JSON)
            mutelist_content: Mutelist content as a dictionary
            provider: Provider name (default: "alibabacloud")
            identity: Alibaba Cloud identity information
        """
        super().__init__(
            mutelist_path=mutelist_path,
            mutelist_content=mutelist_content,
        )
        self.identity = identity
        self.provider = provider

    def is_finding_muted(
        self,
        finding,
        account_id: str = None,
        region: str = None,
        check_id: str = None,
        resource_id: str = None,
    ) -> bool:
        """
        Check if a finding should be muted based on mutelist rules

        Args:
            finding: The finding object to check
            account_id: Alibaba Cloud account ID
            region: Alibaba Cloud region ID
            check_id: Check identifier
            resource_id: Resource identifier

        Returns:
            bool: True if the finding is muted, False otherwise
        """
        # Use the parent class implementation which handles the core logic
        return super().is_muted(
            account_uid=account_id or getattr(finding, "account_uid", None),
            region=region or getattr(finding, "region", None),
            check_id=check_id or getattr(finding, "check_metadata", {}).get("CheckID"),
            resource_id=resource_id or getattr(finding, "resource_uid", None),
            finding_tags=getattr(finding, "resource_tags", []),
        )
