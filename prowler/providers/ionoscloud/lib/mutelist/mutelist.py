from prowler.lib.check.models import CheckReportIonosCloud
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_tags


class IonosCloudMutelist(Mutelist):
    """Mutelist implementation for IONOS Cloud findings."""

    def __init__(
        self,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        account_id: str = "",
    ):
        self.account_id = account_id
        super().__init__(
            mutelist_path=mutelist_path or "",
            mutelist_content=mutelist_content or {},
        )

    def is_finding_muted(
        self,
        finding: CheckReportIonosCloud,
    ) -> bool:
        try:
            account_id = self.account_id
            check_id = finding.check_metadata.CheckID
            location = getattr(finding, "location", "")
            resource_id = getattr(finding, "resource_id", "")
            resource_tags = {}

            if hasattr(finding, "resource_tags") and finding.resource_tags:
                resource_tags = unroll_tags(finding.resource_tags)

            return self.is_muted(
                account_id,
                check_id,
                location,
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
        location: str,
        resource_id: str,
        resource_tags: dict = None,
    ) -> bool:
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
                check_mutelist = {**check_mutelist, **checks.get(check_id, {})}

            if not check_mutelist:
                return False

            regions = check_mutelist.get("Regions", [])
            if regions and "*" not in regions and location not in regions:
                return False

            resources = check_mutelist.get("Resources", [])
            if resources and "*" not in resources and resource_id not in resources:
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
                if resource_id in exceptions.get("Resources", []):
                    return False
                if location in exceptions.get("Regions", []):
                    return False

            return True

        except Exception as error:
            logger.error(
                f"Error checking mutelist: {error.__class__.__name__}: {error}"
            )
            return False
