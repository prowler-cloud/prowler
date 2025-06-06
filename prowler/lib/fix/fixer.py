from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Union

from colorama import Fore, Style

from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger


class Fixer(ABC):
    """Base class for all fixers"""

    def __init__(
        self,
        description: str,
        cost_impact: bool = False,
        cost_description: Optional[str] = None,
    ):
        """
        Initialize base fixer class.

        Args:
            description (str): Description of the fixer
            cost_impact (bool): Whether the fixer has a cost impact
            cost_description (Optional[str]): Description of the cost impact
        """
        self._client = None
        self.logger = logger
        self.description = description
        self.cost_impact = cost_impact
        self.cost_description = cost_description

    def _get_fixer_info(self) -> Dict:
        """Get fixer metadata"""
        return {
            "description": self.description,
            "cost_impact": self.cost_impact,
            "cost_description": self.cost_description,
        }

    @abstractmethod
    def fix(self, finding: Optional[Check_Report] = None, **kwargs) -> bool:
        """
        Main method that all fixers must implement.

        Args:
            finding (Optional[Check_Report]): Finding to fix
            **kwargs: Additional arguments specific to each fixer

        Returns:
            bool: True if fix was successful, False otherwise
        """

    @property
    def client(self):
        """Lazy load of the client"""
        return self._client

    @classmethod
    def get_fixer_for_finding(
        cls,
        finding: Check_Report,
    ) -> Optional["Fixer"]:
        """
        Factory method to get the appropriate fixer for a finding.

        Args:
            finding (Check_Report): The finding to fix
            credentials (Optional[Dict]): Optional credentials for isolated execution
            session_config (Optional[Dict]): Optional session configuration

        Returns:
            Optional[Fixer]: An instance of the appropriate fixer or None if no fixer is found
        """
        try:
            # Extract check name from finding
            check_name = finding.check_metadata.CheckID
            if not check_name:
                logger.error("Finding does not contain a check ID")
                return None

            # Convert check name to fixer class name
            # Example: rds_instance_no_public_access -> RdsInstanceNoPublicAccessFixer
            fixer_name = (
                "".join(word.capitalize() for word in check_name.split("_")) + "Fixer"
            )

            # Get provider from finding
            provider = finding.check_metadata.Provider
            if not provider:
                logger.error("Finding does not contain a provider")
                return None

            # Get service name from finding
            service_name = finding.check_metadata.ServiceName

            # Import the fixer class dynamically
            try:
                # Build the module path using the service name and check name
                module_path = f"prowler.providers.{provider.lower()}.services.{service_name}.{check_name}.{check_name}_fixer"
                module = __import__(module_path, fromlist=[fixer_name])
                fixer_class = getattr(module, fixer_name)
                return fixer_class()
            except (ImportError, AttributeError):
                print(
                    f"\n{Fore.YELLOW}No fixer available for check {check_name}{Style.RESET_ALL}"
                )
                return None

        except Exception as e:
            logger.error(f"Error getting fixer for finding: {str(e)}")
            return None

    @classmethod
    def run_fixer(
        cls,
        findings: Union[Check_Report, List[Check_Report]],
    ) -> int:
        """
        Method to execute the fixer on one or multiple findings.

        Args:
            findings (Union[Check_Report, List[Check_Report]]): A single finding or list of findings to fix

        Returns:
            int: Number of findings successfully fixed
        """
        try:
            # Handle single finding case
            if isinstance(findings, Check_Report):
                if findings.status != "FAIL":
                    return 0
                check_id = findings.check_metadata.CheckID
                if not check_id:
                    return 0
                return cls.run_individual_fixer(check_id, [findings])

            # Handle multiple findings case
            fixed_findings = 0
            findings_by_check = {}

            # Group findings by check
            for finding in findings:
                if finding.status != "FAIL":
                    continue
                check_id = finding.check_metadata.CheckID
                if not check_id:
                    continue
                if check_id not in findings_by_check:
                    findings_by_check[check_id] = []
                findings_by_check[check_id].append(finding)

            # Process each check
            for check_id, check_findings in findings_by_check.items():
                fixed_findings += cls.run_individual_fixer(check_id, check_findings)

            return fixed_findings

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return 0

    @classmethod
    def run_individual_fixer(cls, check_id: str, findings: List[Check_Report]) -> int:
        """
        Run the fixer for a specific check ID.

        Args:
            check_id (str): The check ID to fix
            findings (List[Check_Report]): List of findings to process

        Returns:
            int: Number of findings successfully fixed
        """
        try:
            # Filter findings for this check_id and status FAIL
            check_findings = [
                finding
                for finding in findings
                if finding.check_metadata.CheckID == check_id
                and finding.status == "FAIL"
            ]

            if not check_findings:
                return 0

            # Get the fixer for this check
            fixer = cls.get_fixer_for_finding(check_findings[0])
            if not fixer:
                return 0

            # Print fixer information
            print(f"\n{Fore.CYAN}Fixer Information for {check_id}:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}================================={Style.RESET_ALL}")
            for key, value in fixer._get_fixer_info().items():
                print(f"{Fore.CYAN}{key}: {Style.RESET_ALL}{value}")
            print(f"{Fore.CYAN}================================={Style.RESET_ALL}\n")

            print(
                f"\nFixing fails for check {Fore.YELLOW}{check_id}{Style.RESET_ALL}..."
            )

            fixed_findings = 0
            for finding in check_findings:
                if fixer.fix(finding=finding):
                    fixed_findings += 1
                    print(f"\t{Fore.GREEN}DONE{Style.RESET_ALL}")
                else:
                    print(f"\t{Fore.RED}ERROR{Style.RESET_ALL}")

            return fixed_findings

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return 0
