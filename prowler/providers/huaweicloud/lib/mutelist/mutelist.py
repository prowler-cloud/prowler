from prowler.lib.check.models import CheckReportHuaweiCloud
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_tags


class HuaweiCloudMutelist(Mutelist):
    """
    HuaweiCloudMutelist class extends the base Mutelist for Huawei Cloud-specific functionality.

    This class handles muting/filtering of findings for Huawei Cloud resources.

    Attributes:
        account_id: The Huawei Cloud account ID
        mutelist: The parsed mutelist data
    """

    def __init__(
        self,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        account_id: str = "",
    ):
        """
        Initialize the HuaweiCloudMutelist.

        Args:
            mutelist_path: Path to the mutelist file
            mutelist_content: Dictionary containing mutelist content
            account_id: The Huawei Cloud account ID
        """
        self.account_id = account_id
        super().__init__(
            mutelist_path=mutelist_path or "",
            mutelist_content=mutelist_content or {},
        )

    def is_finding_muted(
        self,
        finding: CheckReportHuaweiCloud,
        account_id: str,
    ) -> bool:
        """
        Check if a finding is muted based on the mutelist.

        Args:
            finding: The finding object to check.
            account_id: The Huawei Cloud account ID to use for mutelist evaluation.

        Returns:
            bool: True if the finding is muted, False otherwise.
        """
        try:
            check_id = finding.check_metadata.CheckID
            region = finding.region if hasattr(finding, "region") else ""
            resource_id = finding.resource_id if hasattr(finding, "resource_id") else ""
            resource_tags = {}

            if hasattr(finding, "resource_tags") and finding.resource_tags:
                resource_tags = unroll_tags(finding.resource_tags)

            return self.is_muted(
                account_id,
                check_id,
                region,
                resource_id,
                resource_tags,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False

    def is_muted(
        self,
        account_id: str,
        check_id: str,
        region: str,
        resource_id: str,
        resource_tags: dict = None,
    ) -> bool:
        """
        Check if a finding should be muted.

        Args:
            account_id: The Huawei Cloud account ID
            check_id: The check ID
            region: The region ID
            resource_id: The resource ID
            resource_tags: Dictionary of resource tags

        Returns:
            True if the finding should be muted, False otherwise
        """
        if not self.mutelist:
            return False

        try:
            accounts = self.mutelist.get("Accounts", {})
            if not accounts:
                return False

            account_mutelist = accounts.get("*", {})
            if account_id in accounts:
                specific_account = accounts.get(account_id, {})
                account_mutelist = {**account_mutelist, **specific_account}

            if not account_mutelist:
                return False

            checks = account_mutelist.get("Checks", {})

            check_mutelist = checks.get("*", {})
            if check_id in checks:
                specific_check = checks.get(check_id, {})
                check_mutelist = {**check_mutelist, **specific_check}

            if not check_mutelist:
                return False

            regions = check_mutelist.get("Regions", [])
            if regions and "*" not in regions and region not in regions:
                return False

            resources = check_mutelist.get("Resources", [])
            if resources:
                if "*" not in resources and resource_id not in resources:
                    return False

            tags = check_mutelist.get("Tags", [])
            if tags and resource_tags:
                tag_match = False
                for tag_filter in tags:
                    if "=" in tag_filter:
                        key, value = tag_filter.split("=", 1)
                        if key in resource_tags:
                            if value == "*" or resource_tags[key] == value:
                                tag_match = True
                                break

                if not tag_match:
                    return False

            exceptions = check_mutelist.get("Exceptions", {})
            if exceptions:
                exception_resources = exceptions.get("Resources", [])
                if resource_id in exception_resources:
                    return False

                exception_regions = exceptions.get("Regions", [])
                if region in exception_regions:
                    return False

            return True

        except Exception as error:
            logger.error(
                f"Error checking mutelist: {error.__class__.__name__}: {error}"
            )
            return False
