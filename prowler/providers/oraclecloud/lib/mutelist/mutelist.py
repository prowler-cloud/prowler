from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class OCIMutelist(Mutelist):
    """
    OCIMutelist class manages the mutelist functionality for OCI provider.

    This class extends the base Mutelist class to provide OCI-specific functionality
    for muting findings based on tenancy, check, region, resource, and tags.
    """

    def __init__(
        self,
        mutelist_content: dict = {},
        mutelist_path: str = None,
        tenancy_id: str = "",
    ) -> "OCIMutelist":
        """
        Initialize the OCIMutelist.

        Args:
            mutelist_content (dict): The mutelist content as a dictionary.
            mutelist_path (str): The path to the mutelist file.
            tenancy_id (str): The OCI tenancy ID.
        """
        self._mutelist = mutelist_content
        self._mutelist_file_path = mutelist_path
        self._tenancy_id = tenancy_id

        if mutelist_path:
            # Load mutelist from local file
            self.get_mutelist_file_from_local_file(mutelist_path)

        if self._mutelist:
            self._mutelist = self.validate_mutelist(self._mutelist)

    def is_finding_muted(
        self,
        finding,
        tenancy_id: str,
    ) -> bool:
        """
        Check if a finding is muted based on the mutelist.

        Args:
            finding: The finding object to check (should have check_metadata, region, resource_id, resource_tags).
            tenancy_id (str): The OCI tenancy ID.

        Returns:
            bool: True if the finding is muted, False otherwise.
        """
        try:
            check_id = finding.check_metadata.CheckID
            region = finding.region if hasattr(finding, "region") else ""
            resource_id = finding.resource_id if hasattr(finding, "resource_id") else ""
            resource_tags = {}

            # Handle resource tags
            if hasattr(finding, "resource_tags") and finding.resource_tags:
                resource_tags = unroll_dict(unroll_tags(finding.resource_tags))

            return self.is_muted(
                tenancy_id,
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
        tenancy_id: str,
        check_id: str,
        region: str,
        resource_id: str,
        resource_tags: dict,
    ) -> bool:
        """
        Check if a specific combination is muted.

        Args:
            tenancy_id (str): The OCI tenancy ID.
            check_id (str): The check ID.
            region (str): The OCI region.
            resource_id (str): The resource ID (OCID).
            resource_tags (dict): The resource tags.

        Returns:
            bool: True if muted, False otherwise.
        """
        try:
            if not self._mutelist:
                return False

            # Check if mutelist has Accounts/Tenancies section
            tenancies = self._mutelist.get("Accounts", {})
            if not tenancies:
                # Try with "Tenancies" key for OCI-specific mutelist
                tenancies = self._mutelist.get("Tenancies", {})

            # Check for wildcard or specific tenancy
            tenancy_mutelist = tenancies.get("*", {})
            if tenancy_id in tenancies:
                # Merge with specific tenancy rules
                specific_tenancy = tenancies.get(tenancy_id, {})
                tenancy_mutelist = {**tenancy_mutelist, **specific_tenancy}

            if not tenancy_mutelist:
                return False

            # Get checks for this tenancy
            checks = tenancy_mutelist.get("Checks", {})

            # Check for wildcard or specific check
            check_mutelist = checks.get("*", {})
            if check_id in checks:
                specific_check = checks.get(check_id, {})
                check_mutelist = {**check_mutelist, **specific_check}

            if not check_mutelist:
                return False

            # Check regions
            regions = check_mutelist.get("Regions", [])
            if regions and "*" not in regions and region not in regions:
                return False

            # Check resources
            resources = check_mutelist.get("Resources", [])
            if resources:
                if "*" not in resources and resource_id not in resources:
                    return False

            # Check tags
            tags = check_mutelist.get("Tags", [])
            if tags and resource_tags:
                # Check if any tag matches
                tag_match = False
                for tag_filter in tags:
                    # Tag filter format: "key=value" or "key=*"
                    if "=" in tag_filter:
                        key, value = tag_filter.split("=", 1)
                        if key in resource_tags:
                            if value == "*" or resource_tags[key] == value:
                                tag_match = True
                                break

                if not tag_match:
                    return False

            # Check exceptions (resources that should NOT be muted)
            exceptions = check_mutelist.get("Exceptions", {})
            if exceptions:
                exception_resources = exceptions.get("Resources", [])
                if resource_id in exception_resources:
                    return False

                exception_regions = exceptions.get("Regions", [])
                if region in exception_regions:
                    return False

            # If we passed all checks, the finding is muted
            return True

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
