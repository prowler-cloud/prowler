import datetime
from typing import Generator

from prowler.config.config import valid_severities
from prowler.lib.check.check import execute, import_check, update_audit_metadata
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.models import CheckMetadata
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.scan.exceptions.exceptions import ScanInvalidSeverityError
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class Scan:
    _provider: Provider
    # Refactor(Core): This should replace the Audit_Metadata
    _number_of_checks_to_execute: int = 0
    _number_of_checks_completed: int = 0
    # TODO the str should be a set of Check objects
    _checks_to_execute: set[str]
    _service_checks_to_execute: dict[str, set[str]]
    _service_checks_completed: dict[str, set[str]]
    _progress: float = 0.0
    _findings: list = []
    _duration: int = 0

    def __init__(
        self,
        provider: Provider,
        checks: list[str] = None,
        services: list[str] = None,
        compliances: list[str] = None,
        categories: set[str] = [],
        severity: list[str] = None,
    ):
        """
        Scan is the class that executes the checks and yields the progress and the findings.

        Params:
            provider: Provider -> The provider to scan
            checks: list[str] -> The checks to execute
            services: list[str] -> The services to scan
            compliances: list[str] -> The compliances to check
            categories: set[str] -> The categories to check
            severity: list[str] -> The severity of the checks
        """
        self._provider = provider

        # Load bulk compliance frameworks
        bulk_compliance_frameworks = Compliance.get_bulk(provider.type)

        # Get bulk checks metadata for the provider
        bulk_checks_metadata = CheckMetadata.get_bulk(provider.type)
        # Complete checks metadata with the compliance framework specification
        bulk_checks_metadata = update_checks_metadata_with_compliance(
            bulk_compliance_frameworks, bulk_checks_metadata
        )

        # Validate severity
        if severity and not set(severity).issubset(valid_severities):
            raise ScanInvalidSeverityError(
                f"Invalid severity: {severity}. Valid severities are: {valid_severities}"
            )

        # Load checks to execute
        self._checks_to_execute = load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            bulk_compliance_frameworks=bulk_compliance_frameworks,
            check_list=checks,
            service_list=services,
            compliance_frameworks=compliances,
            categories=categories,
            severities=severity,
            provider=provider.type,
            checks_file=None,
        )

        # TODO This should be done depending on the scan args (future feature)
        # Discard threat detection checks
        if "cloudtrail_threat_detection_enumeration" in self._checks_to_execute:
            self._checks_to_execute.remove("cloudtrail_threat_detection_enumeration")
        if (
            "cloudtrail_threat_detection_privilege_escalation"
            in self._checks_to_execute
        ):
            self._checks_to_execute.remove(
                "cloudtrail_threat_detection_privilege_escalation"
            )

        self._number_of_checks_to_execute = len(self._checks_to_execute)

        service_checks_to_execute = get_service_checks_to_execute(
            self._checks_to_execute
        )
        service_checks_completed = dict()

        self._service_checks_to_execute = service_checks_to_execute
        self._service_checks_completed = service_checks_completed

    @property
    def checks_to_execute(self) -> set[str]:
        return self._checks_to_execute

    @property
    def service_checks_to_execute(self) -> dict[str, set[str]]:
        return self._service_checks_to_execute

    @property
    def service_checks_completed(self) -> dict[str, set[str]]:
        return self._service_checks_completed

    @property
    def provider(self) -> Provider:
        return self._provider

    @property
    def progress(self) -> float:
        return (
            self._number_of_checks_completed / self._number_of_checks_to_execute * 100
        )

    @property
    def duration(self) -> int:
        return self._duration

    @property
    def findings(self) -> list:
        return self._findings

    def scan(
        self,
        custom_checks_metadata: dict = {},
    ) -> Generator[tuple[float, list[Finding]], None, None]:
        """
        Executes the scan by iterating over the checks to execute and executing each check.
        Yields the progress and findings for each check.

        Args:
            custom_checks_metadata (dict): Custom metadata for the checks (default: {}).

        Yields:
            Tuple[float, list[Finding]]: A tuple containing the progress and findings for each check.

        Raises:
            ModuleNotFoundError: If the check does not exist in the provider or is from another provider.
            Exception: If any other error occurs during the execution of a check.
        """
        try:
            checks_to_execute = self.checks_to_execute
            # Initialize the Audit Metadata
            # TODO: this should be done in the provider class
            # Refactor(Core): Audit manager?
            self._provider.audit_metadata = Audit_Metadata(
                services_scanned=0,
                expected_checks=checks_to_execute,
                completed_checks=0,
                audit_progress=0,
            )

            start_time = datetime.datetime.now()

            for check_name in checks_to_execute:
                try:
                    # Recover service from check name
                    service = get_service_name_from_check_name(check_name)
                    try:
                        # Import check module
                        check_module_path = f"prowler.providers.{self._provider.type}.services.{service}.{check_name}.{check_name}"
                        lib = import_check(check_module_path)
                        # Recover functions from check
                        check_to_execute = getattr(lib, check_name)
                        check = check_to_execute()
                    except ModuleNotFoundError:
                        logger.error(
                            f"Check '{check_name}' was not found for the {self._provider.type.upper()} provider"
                        )
                        continue
                    # Execute the check
                    check_findings = execute(
                        check,
                        self._provider,
                        custom_checks_metadata,
                        output_options=None,
                    )

                    # Store findings
                    self._findings.extend(check_findings)

                    # Remove the executed check
                    self._service_checks_to_execute[service].remove(check_name)
                    if len(self._service_checks_to_execute[service]) == 0:
                        self._service_checks_to_execute.pop(service, None)
                    # Add the completed check
                    if service not in self._service_checks_completed:
                        self._service_checks_completed[service] = set()
                    self._service_checks_completed[service].add(check_name)
                    self._number_of_checks_completed += 1

                    # This should be done just once all the service's checks are completed
                    # This metadata needs to get to the services not within the provider
                    # since it is present in the Scan class
                    self._provider.audit_metadata = update_audit_metadata(
                        self._provider.audit_metadata,
                        self.get_completed_services(),
                        self.get_completed_checks(),
                    )

                    findings = [
                        Finding.generate_output(
                            self._provider, finding, output_options=None
                        )
                        for finding in check_findings
                    ]

                    yield self.progress, findings
                # If check does not exists in the provider or is from another provider
                except ModuleNotFoundError:
                    logger.error(
                        f"Check '{check_name}' was not found for the {self._provider.type.upper()} provider"
                    )
                except Exception as error:
                    logger.error(
                        f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            # Update the scan duration when all checks are completed
            self._duration = int((datetime.datetime.now() - start_time).total_seconds())
        except Exception as error:
            logger.error(
                f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_completed_services(self) -> set[str]:
        """
        get_completed_services returns the services that have been completed.

        Example:
            get_completed_services() -> {"ec2", "s3"}
        """
        return self._service_checks_completed.keys()

    def get_completed_checks(self) -> set[str]:
        """
        get_completed_checks returns the checks that have been completed.

        Example:
            get_completed_checks() -> {"ec2_instance_public_ip", "s3_bucket_public"}
        """
        completed_checks = set()
        for checks in self._service_checks_completed.values():
            completed_checks.update(checks)
        return completed_checks


def get_service_name_from_check_name(check_name: str) -> str:
    """
    get_service_name_from_check_name returns the service name for a given check name.

    Example:
        get_service_name_from_check_name("ec2_instance_public") -> "ec2"
    """
    return check_name.split("_")[0]


def get_service_checks_to_execute(checks_to_execute: set[str]) -> dict[str, set[str]]:
    """
    get_service_checks_to_execute returns a dictionary with the services and the checks to execute.

    Example:
        get_service_checks_to_execute({"accessanalyzer_enabled", "ec2_instance_public_ip"})
        -> {"accessanalyzer": {"accessanalyzer_enabled"}, "ec2": {"ec2_instance_public_ip"}}
    """
    service_checks_to_execute = dict()
    for check in checks_to_execute:
        # check -> accessanalyzer_enabled
        # service -> accessanalyzer
        service = get_service_name_from_check_name(check)
        if service not in service_checks_to_execute:
            service_checks_to_execute[service] = set()
        service_checks_to_execute[service].add(check)
    return service_checks_to_execute
