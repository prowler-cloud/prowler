import re
from abc import ABC, abstractmethod

import yaml

from prowler.lib.logger import logger
from prowler.lib.mutelist.models import mutelist_schema
from prowler.lib.outputs.common import Status
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class Mutelist(ABC):
    """
    Abstract base class for managing a mutelist.

    Attributes:
        _mutelist (dict): Dictionary containing information about muted checks for different accounts.
        _mutelist_file_path (str): Path to the mutelist file.
        MUTELIST_KEY (str): Key used to access the mutelist in the mutelist file.

    Methods:
        __init__: Initializes a Mutelist object.
        mutelist: Property that returns the mutelist dictionary.
        mutelist_file_path: Property that returns the mutelist file path.
        is_finding_muted: Abstract method to check if a finding is muted.
        get_mutelist_file_from_local_file: Retrieves the mutelist file from a local file.
        validate_mutelist: Validates the mutelist against a schema.
        is_muted: Checks if a finding is muted for the audited account, check, region, resource, and tags.
        is_muted_in_check: Checks if a check is muted.
        is_excepted: Checks if the account, region, resource, and tags are excepted based on the exceptions.
    """

    _mutelist: dict = {}
    _mutelist_file_path: str = None

    MUTELIST_KEY = "Mutelist"

    def __init__(
        self, mutelist_path: str = "", mutelist_content: dict = {}
    ) -> "Mutelist":
        if mutelist_path:
            self._mutelist_file_path = mutelist_path
            self.get_mutelist_file_from_local_file(mutelist_path)
        else:
            self._mutelist = mutelist_content

        if self._mutelist:
            self.validate_mutelist()

    @property
    def mutelist(self) -> dict:
        return self._mutelist

    @property
    def mutelist_file_path(self) -> dict:
        return self._mutelist_file_path

    @abstractmethod
    def is_finding_muted(self) -> bool:
        raise NotImplementedError

    def get_mutelist_file_from_local_file(self, mutelist_path: str):
        try:
            with open(mutelist_path) as f:
                self._mutelist = yaml.safe_load(f)[self.MUTELIST_KEY]
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
            )

    def validate_mutelist(self) -> bool:
        try:
            self._mutelist = mutelist_schema.validate(self._mutelist)
            return True
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- Mutelist YAML is malformed - {error}[{error.__traceback__.tb_lineno}]"
            )
            self._mutelist = {}
            return False

    def is_muted(
        self,
        audited_account: str,
        check: str,
        finding_region: str,
        finding_resource: str,
        finding_tags,
    ) -> bool:
        """
        Check if the provided finding is muted for the audited account, check, region, resource and tags.

        The Mutelist works in a way that each field is ANDed, so if a check is muted for an account, region, resource and tags, it will be muted.
        The exceptions are ORed, so if a check is excepted for an account, region, resource or tags, it will not be muted.
        The only particularity is the tags, which are ORed.

        So, for the following Mutelist:
        ```
        Mutelist:
            Accounts:
                '*':
                Checks:
                    ec2_instance_detailed_monitoring_enabled:
                        Regions: ['*']
                        Resources:
                            - 'i-123456789'
                        Tags:
                            - 'Name=AdminInstance | Environment=Prod'
        ```
        The check `ec2_instance_detailed_monitoring_enabled` will be muted for all accounts and regions and for the resource_id 'i-123456789' with at least one of the tags 'Name=AdminInstance' or 'Environment=Prod'.

        Args:
            mutelist (dict): Dictionary containing information about muted checks for different accounts.
            audited_account (str): The account being audited.
            check (str): The check to be evaluated for muting.
            finding_region (str): The region where the finding occurred.
            finding_resource (str): The resource related to the finding.
            finding_tags: The tags associated with the finding.

        Returns:
            bool: True if the finding is muted for the audited account, check, region, resource and tags., otherwise False.
        """
        try:
            # By default is not muted
            is_finding_muted = False

            # We always check all the accounts present in the mutelist
            # if one mutes the finding we set the finding as muted
            for account in self._mutelist.get("Accounts", []):
                if account == audited_account or account == "*":
                    if self.is_muted_in_check(
                        self._mutelist["Accounts"][account]["Checks"],
                        audited_account,
                        check,
                        finding_region,
                        finding_resource,
                        finding_tags,
                    ):
                        is_finding_muted = True
                        break

            return is_finding_muted
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
            )
            return False

    def is_muted_in_check(
        self,
        muted_checks,
        audited_account,
        check,
        finding_region,
        finding_resource,
        finding_tags,
    ) -> bool:
        """
        Check if the provided check is muted.

        Args:
            muted_checks (dict): Dictionary containing information about muted checks.
            audited_account (str): The account to be audited.
            check (str): The check to be evaluated for muting.
            finding_region (str): The region where the finding occurred.
            finding_resource (str): The resource related to the finding.
            finding_tags (str): The tags associated with the finding.

        Returns:
            bool: True if the check is muted, otherwise False.
        """
        try:
            # Default value is not muted
            is_check_muted = False

            for muted_check, muted_check_info in muted_checks.items():
                # map lambda to awslambda
                muted_check = re.sub("^lambda", "awslambda", muted_check)

                check_match = (
                    "*" == muted_check
                    or check == muted_check
                    or self.is_item_matched([muted_check], check)
                )

                # Check if the finding is excepted
                exceptions = muted_check_info.get("Exceptions")
                if (
                    self.is_excepted(
                        exceptions,
                        audited_account,
                        finding_region,
                        finding_resource,
                        finding_tags,
                    )
                    and check_match
                ):
                    # Break loop and return default value since is excepted
                    break

                muted_regions = muted_check_info.get("Regions")
                muted_resources = muted_check_info.get("Resources")
                muted_tags = muted_check_info.get("Tags", "*")
                # We need to set the muted_tags if None, "" or [], so the falsy helps
                if not muted_tags:
                    muted_tags = "*"
                # If there is a *, it affects to all checks
                if check_match:
                    muted_in_check = True
                    muted_in_region = self.is_item_matched(
                        muted_regions, finding_region
                    )
                    muted_in_resource = self.is_item_matched(
                        muted_resources, finding_resource
                    )
                    muted_in_tags = self.is_item_matched(
                        muted_tags, finding_tags, tag=True
                    )

                    # For a finding to be muted requires the following set to True:
                    # - muted_in_check -> True
                    # - muted_in_region -> True
                    # - muted_in_tags -> True
                    # - muted_in_resource -> True
                    # - excepted -> False

                    if (
                        muted_in_check
                        and muted_in_region
                        and muted_in_tags
                        and muted_in_resource
                    ):
                        is_check_muted = True

            return is_check_muted
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
            )
            return False

    def mute_finding(self, finding):
        """
        Check if the provided finding is muted

        Args:
            finding (Finding): The finding to be evaluated for muting.

        Returns:
            Finding: The finding with the status updated if it is muted, otherwise the finding is returned

        """
        try:
            if self.is_muted(
                finding.account_uid,
                finding.metadata.CheckID,
                finding.region,
                finding.resource_uid,
                unroll_dict(unroll_tags(finding.resource_tags)),
            ):
                finding.raw["status"] = finding.status
                finding.status = Status.MUTED
                finding.muted = True
            return finding
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
            )
            return finding

    def is_excepted(
        self,
        exceptions,
        audited_account,
        finding_region,
        finding_resource,
        finding_tags,
    ) -> bool:
        """
        Check if the provided account, region, resource, and tags are excepted based on the exceptions dictionary.

        Args:
            exceptions (dict): Dictionary containing exceptions for different attributes like Accounts, Regions, Resources, and Tags.
            audited_account (str): The account to be audited.
            finding_region (str): The region where the finding occurred.
            finding_resource (str): The resource related to the finding.
            finding_tags (str): The tags associated with the finding.

        Returns:
            bool: True if the account, region, resource, and tags are excepted based on the exceptions, otherwise False.
        """
        try:
            excepted = False
            is_account_excepted = False
            is_region_excepted = False
            is_resource_excepted = False
            is_tag_excepted = False
            if exceptions:
                excepted_accounts = exceptions.get("Accounts", [])
                is_account_excepted = self.is_item_matched(
                    excepted_accounts, audited_account
                )

                excepted_regions = exceptions.get("Regions", [])
                is_region_excepted = self.is_item_matched(
                    excepted_regions, finding_region
                )

                excepted_resources = exceptions.get("Resources", [])
                is_resource_excepted = self.is_item_matched(
                    excepted_resources, finding_resource
                )

                excepted_tags = exceptions.get("Tags", [])
                is_tag_excepted = self.is_item_matched(
                    excepted_tags, finding_tags, tag=True
                )

                if (
                    not is_account_excepted
                    and not is_region_excepted
                    and not is_resource_excepted
                    and not is_tag_excepted
                ):
                    excepted = False
                elif (
                    (is_account_excepted or not excepted_accounts)
                    and (is_region_excepted or not excepted_regions)
                    and (is_resource_excepted or not excepted_resources)
                    and (is_tag_excepted or not excepted_tags)
                ):
                    excepted = True
            return excepted
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
            )
            return False

    @staticmethod
    def is_item_matched(matched_items, finding_items, tag=False) -> bool:
        """
        Check if any of the items in matched_items are present in finding_items.

        Args:
            matched_items (list): List of items to be matched.
            finding_items (str): String to search for matched items.
            tag (bool): If True the search will have a different logic due to the tags being ANDed or ORed:
                - Check of AND logic -> True if all the tags are present in the finding.
                - Check of OR logic -> True if any of the tags is present in the finding.

        Returns:
            bool: True if any of the matched_items are present in finding_items, otherwise False.
        """
        try:
            is_item_matched = False
            if matched_items and (finding_items or finding_items == ""):
                if tag:
                    is_item_matched = True
                for item in matched_items:
                    if item.startswith("*"):
                        item = ".*" + item[1:]
                    if tag:
                        if not re.search(item, finding_items):
                            is_item_matched = False
                            break
                    else:
                        if re.search(item, finding_items):
                            is_item_matched = True
                            break
            return is_item_matched
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__} -- {error}[{error.__traceback__.tb_lineno}]"
            )
            return False
