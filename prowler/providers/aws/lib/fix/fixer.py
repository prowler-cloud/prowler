from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from colorama import Fore, Style

from prowler.lib.check.models import Check_Report_AWS
from prowler.lib.fix.fixer import Fixer, FixerMetadata
from prowler.lib.logger import logger


class AWSFixer(Fixer, ABC):
    """AWS specific fixer implementation"""

    def __init__(
        self, credentials: Optional[Dict] = None, session_config: Optional[Dict] = None
    ):
        super().__init__(credentials, session_config)
        self.service: str = ""
        self.regional_clients: Dict[str, Any] = {}
        self.iam_policy_required: Dict = {}

    @abstractmethod
    def _get_metadata(self) -> FixerMetadata:
        """Each fixer must define its metadata"""

    @abstractmethod
    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """Main method that all fixers must implement"""

    def fix(self, finding: Optional[Check_Report_AWS] = None, **kwargs) -> bool:
        """
        AWS specific method to execute the fixer.
        Determines what type of fixer is needed based on the required parameters.

        Args:
            finding (Check_Report_AWS): Finding to fix
            **kwargs: Additional AWS-specific arguments

        Returns:
            bool: True if fixing was successful, False otherwise
        """
        try:
            check_module_path = f"prowler.providers.aws.services.{finding.check_metadata.ServiceName}.{finding.check_metadata.CheckID}.{finding.check_metadata.CheckID}_fixer"
            lib = __import__(
                check_module_path, fromlist=[f"{finding.check_metadata.CheckID}_fixer"]
            )
            fixer = getattr(lib, "fixer")

            # Determine what type of fixer it is based on its parameters
            fixer_params = fixer.__code__.co_varnames

            # Prepare the arguments for the fixer
            if "region" in fixer_params and "resource_id" in fixer_params:
                print(
                    f"\t{Fore.YELLOW}FIXING{Style.RESET_ALL} {finding.resource_id} in {finding.region}... "
                )
                return fixer(resource_id=finding.resource_id, region=finding.region)
            elif "region" in fixer_params:
                print(f"\t{Fore.YELLOW}FIXING{Style.RESET_ALL} {finding.region}... ")
                return fixer(region=finding.region)
            elif "resource_arn" in fixer_params:
                print(
                    f"\t{Fore.YELLOW}FIXING{Style.RESET_ALL} Resource {finding.resource_arn}... "
                )
                return fixer(resource_arn=finding.resource_arn)
            else:
                print(
                    f"\t{Fore.YELLOW}FIXING{Style.RESET_ALL} Resource {finding.resource_id}... "
                )
                return fixer(resource_id=finding.resource_id)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
