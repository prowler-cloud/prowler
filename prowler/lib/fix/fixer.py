from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Union

from colorama import Fore, Style

from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger


@dataclass
class FixerMetadata:
    """Metadata común para todos los fixers"""

    description: str
    cost_impact: bool = False
    cost_description: Optional[str] = None


class Fixer(ABC):
    """Clase base para todos los fixers"""

    def __init__(
        self, credentials: Optional[Dict] = None, session_config: Optional[Dict] = None
    ):
        self.metadata = self._get_metadata()
        self._client = None
        self.logger = logger
        self.credentials = credentials
        self.session_config = session_config

    @abstractmethod
    def _get_metadata(self) -> FixerMetadata:
        """Cada fixer debe definir su metadata"""

    @abstractmethod
    def fix(self, finding: Optional[Check_Report] = None, **kwargs) -> bool:
        """Método principal que todos los fixers deben implementar"""

    @property
    def client(self):
        """Lazy load del cliente"""
        return self._client

    @classmethod
    def get_fixer_for_finding(
        cls,
        finding: Check_Report,
        credentials: Optional[Dict] = None,
        session_config: Optional[Dict] = None,
    ) -> Optional["Fixer"]:
        """
        Factory method to get the appropriate fixer for a finding
        Args:
            finding: The finding to fix
            credentials: Optional credentials for isolated execution
            session_config: Optional session configuration
        Returns:
            An instance of the appropriate fixer or None if no fixer is found
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
                return fixer_class(
                    credentials=credentials, session_config=session_config
                )
            except (ImportError, AttributeError) as e:
                logger.error(f"Could not import fixer for check {check_name}: {str(e)}")
                return None

        except Exception as e:
            logger.error(f"Error getting fixer for finding: {str(e)}")
            return None

    @classmethod
    def run_fixer(
        cls,
        findings: Union[Check_Report, List[Check_Report]],
        credentials: Optional[Dict] = None,
        session_config: Optional[Dict] = None,
    ) -> int:
        """
        Método para ejecutar el fixer sobre uno o varios findings.

        Args:
            findings: Un finding individual o una lista de findings a arreglar
            credentials: Credenciales opcionales para ejecución aislada
            session_config: Configuración opcional de la sesión

        Returns:
            int: Número de findings arreglados
        """
        try:
            # Handle single finding case
            if isinstance(findings, Check_Report):
                fixer = cls.get_fixer_for_finding(findings, credentials, session_config)
                if not fixer:
                    return 0
                return 1 if fixer.fix(finding=findings) else 0

            # Handle multiple findings case
            fixed_findings = 0
            findings_by_check = {}

            # Group findings by check
            for finding in findings:
                check_id = finding.check_metadata.CheckID
                if not check_id:
                    continue
                if check_id not in findings_by_check:
                    findings_by_check[check_id] = []
                findings_by_check[check_id].append(finding)

            # Process each group of findings
            for check_id, check_findings in findings_by_check.items():
                # Get the fixer for this check using the first finding
                fixer = cls.get_fixer_for_finding(
                    check_findings[0], credentials, session_config
                )
                if not fixer:
                    continue

                print(
                    f"\nFixing fails for check {Fore.YELLOW}{check_id}{Style.RESET_ALL}..."
                )
                for finding in check_findings:
                    if finding.status == "FAIL":
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
