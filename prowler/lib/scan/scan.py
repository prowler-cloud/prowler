import datetime
from typing import Dict, Generator, List, Optional, Set, Tuple

from prowler.lib.check.check import (
    execute,
    import_check,
    list_services,
    update_audit_metadata,
)
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.models import CheckMetadata, Severity
from prowler.lib.logger import logger
from prowler.lib.outputs.common import Status
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.outputs import extract_findings_statistics
from prowler.lib.scan.exceptions.exceptions import (
    ScanInvalidCategoryError,
    ScanInvalidCheckError,
    ScanInvalidComplianceFrameworkError,
    ScanInvalidServiceError,
    ScanInvalidSeverityError,
    ScanInvalidStatusError,
)
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class Scan:
    _provider: Provider
    _checks_to_execute: List[str]
    _service_checks_map: Dict[str, Set[str]]
    _completed_checks: Set[str]
    _progress: float = 0.0
    _findings: List[Finding] = []
    _duration: int = 0
    _statuses: Optional[List[Status]] = None

    def __init__(
        self,
        provider: Provider,
        checks: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        compliances: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        excluded_checks: Optional[List[str]] = None,
        excluded_services: Optional[List[str]] = None,
        status: Optional[List[str]] = None,
    ):
        """
        Scan is the class that executes the checks and yields the progress and the findings.

        Params:
            provider: Provider -> The provider to scan
            checks: list[str] -> The checks to execute
            services: list[str] -> The services to scan
            compliances: list[str] -> The compliances to check
            categories: list[str] -> The categories of the checks
            severities: list[str] -> The severities of the checks
            excluded_checks: list[str] -> The checks to exclude
            excluded_services: list[str] -> The services to exclude
            status: list[str] -> The status of the checks

        Raises:
            ScanInvalidCheckError: If the check does not exist in the provider or is from another provider.
            ScanInvalidServiceError: If the service does not exist in the provider.
            ScanInvalidComplianceFrameworkError: If the compliance framework does not exist in the provider.
            ScanInvalidCategoryError: If the category does not exist in the provider.
            ScanInvalidSeverityError: If the severity does not exist in the provider.
            ScanInvalidStatusError: If the status does not exist in the provider.
        """
        self._provider = provider
        self._statuses = self._validate_statuses(status)

        bulk_compliance_frameworks = Compliance.get_bulk(provider.type)
        bulk_checks_metadata = self._load_checks_metadata(bulk_compliance_frameworks)

        self._validate_inputs(
            checks,
            services,
            compliances,
            categories,
            severities,
            bulk_checks_metadata,
            bulk_compliance_frameworks,
        )

        self._checks_to_execute = self._init_checks_to_execute(
            bulk_checks_metadata,
            bulk_compliance_frameworks,
            checks,
            services,
            compliances,
            categories,
            severities,
            excluded_checks,
            excluded_services,
        )

        self._service_checks_map = get_service_checks_mapping(self._checks_to_execute)
        self._completed_checks = set()

    def _validate_statuses(
        self, statuses: Optional[List[str]]
    ) -> Optional[List[Status]]:
        """Validate and convert status strings to Status enums."""
        if not statuses:
            return None

        validated = []
        for status in statuses:
            try:
                validated.append(Status(status))
            except ValueError:
                raise ScanInvalidStatusError(f"Invalid status: {status}")
        return validated

    def _load_checks_metadata(self, bulk_compliance_frameworks: dict) -> dict:
        """Load and enhance checks metadata with compliance information."""
        bulk_checks_metadata = CheckMetadata.get_bulk(self._provider.type)
        return update_checks_metadata_with_compliance(
            bulk_compliance_frameworks, bulk_checks_metadata
        )

    def _validate_inputs(
        self,
        checks: Optional[List[str]],
        services: Optional[List[str]],
        compliances: Optional[List[str]],
        categories: Optional[List[str]],
        severities: Optional[List[str]],
        bulk_checks_metadata: dict,
        bulk_compliance_frameworks: dict,
    ):
        """Validate all input parameters against provider capabilities."""
        valid_services = list_services(self._provider.type)
        valid_categories = self._extract_valid_categories(bulk_checks_metadata)

        self._validate_checks(checks, bulk_checks_metadata)
        self._validate_services(services, valid_services)
        self._validate_compliances(compliances, bulk_compliance_frameworks)
        self._validate_categories(categories, valid_categories)
        self._validate_severities(severities)

    def _extract_valid_categories(self, checks_metadata: dict) -> Set[str]:
        """Extract unique categories from checks metadata."""
        return {
            category
            for metadata in checks_metadata.values()
            for category in metadata.Categories
        }

    def _validate_checks(self, checks: Optional[List[str]], metadata: dict):
        """Validate requested checks exist in provider."""
        if checks:
            invalid = [check for check in checks if check not in metadata]
            if invalid:
                raise ScanInvalidCheckError(f"Invalid checks: {', '.join(invalid)}")

    def _validate_services(self, services: Optional[List[str]], valid_services: list):
        """Validate requested services exist in provider."""
        if services:
            invalid = [srv for srv in services if srv not in valid_services]
            if invalid:
                raise ScanInvalidServiceError(f"Invalid services: {', '.join(invalid)}")

    def _validate_compliances(self, compliances: Optional[List[str]], frameworks: dict):
        """Validate compliance frameworks exist."""
        if compliances:
            invalid = [comp for comp in compliances if comp not in frameworks]
            if invalid:
                raise ScanInvalidComplianceFrameworkError(
                    f"Invalid compliances: {', '.join(invalid)}"
                )

    def _validate_categories(
        self, categories: Optional[List[str]], valid_categories: Set[str]
    ):
        """Validate categories exist in provider checks."""
        if categories:
            invalid = [cat for cat in categories if cat not in valid_categories]
            if invalid:
                raise ScanInvalidCategoryError(
                    f"Invalid categories: {', '.join(invalid)}"
                )

    def _validate_severities(self, severities: Optional[List[str]]):
        """Validate severity values are valid."""
        if severities:
            try:
                [Severity(sev) for sev in severities]
            except ValueError as e:
                raise ScanInvalidSeverityError(f"Invalid severity: {e}")

    def _init_checks_to_execute(
        self,
        bulk_checks_metadata: dict,
        bulk_compliance_frameworks: dict,
        checks: Optional[List[str]],
        services: Optional[List[str]],
        compliances: Optional[List[str]],
        categories: Optional[List[str]],
        severities: Optional[List[str]],
        excluded_checks: Optional[List[str]],
        excluded_services: Optional[List[str]],
    ) -> List[str]:
        """Load and filter checks based on configuration."""
        checks = load_checks_to_execute(
            bulk_checks_metadata=bulk_checks_metadata,
            bulk_compliance_frameworks=bulk_compliance_frameworks,
            check_list=checks,
            service_list=services,
            compliance_frameworks=compliances,
            categories=categories,
            severities=severities,
            provider=self._provider.type,
        )

        if excluded_checks:
            checks = [c for c in checks if c not in excluded_checks]

        if excluded_services:
            excluded_services_set = set(excluded_services)
            checks = [
                c
                for c in checks
                if get_service_from_check(c) not in excluded_services_set
            ]

        return sorted(checks)

    @property
    def total_checks(self) -> int:
        return len(self._checks_to_execute)

    @property
    def completed_checks(self) -> int:
        return len(self._completed_checks)

    @property
    def progress(self) -> float:
        return (
            (self.completed_checks / self.total_checks * 100)
            if self.total_checks
            else 0
        )

    @property
    def remaining_services(self) -> Dict[str, Set[str]]:
        return {
            service: checks
            for service, checks in self._service_checks_map.items()
            if checks
        }

    def scan(self) -> Generator[Tuple[float, List[Finding], dict], None, None]:
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
        self._provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=self._checks_to_execute,
            completed_checks=0,
            audit_progress=0,
        )

        start_time = datetime.datetime.now()

        for check_name in self._checks_to_execute:
            service = get_service_from_check(check_name)
            try:
                check_module = self._import_check_module(check_name, service)
                findings = self._execute_check(check_module, check_name)
                filtered_findings = self._filter_findings_by_status(findings)
            except Exception as error:
                logger.error(f"{check_name} failed: {error}")
                continue

            self._update_scan_state(check_name, service, filtered_findings)
            stats = extract_findings_statistics(filtered_findings)

            findings = []
            for finding in filtered_findings:
                try:
                    findings.append(
                        Finding.generate_output(
                            self._provider, finding, output_options=None
                        )
                    )
                except Exception:
                    continue

            yield self.progress, findings, stats

        self._duration = int((datetime.datetime.now() - start_time).total_seconds())

    def _import_check_module(self, check_name: str, service: str):
        """Dynamically import check module."""
        module_path = (
            f"prowler.providers.{self._provider.type}.services."
            f"{service}.{check_name}.{check_name}"
        )
        try:
            return import_check(module_path)
        except ModuleNotFoundError:
            logger.error(
                f"Check '{check_name}' not found for {self._provider.type.upper()}"
            )
            raise

    def _execute_check(self, check_module, check_name: str) -> List[Finding]:
        """Execute a single check and return its findings."""
        check_func = getattr(check_module, check_name)
        return execute(check_func(), self._provider, {}, None)

    def _filter_findings_by_status(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings based on configured status filters."""
        if not self._statuses:
            return findings
        return [f for f in findings if f.status in self._statuses]

    def _update_scan_state(
        self, check_name: str, service: str, findings: List[Finding]
    ):
        """Update scan state after check completion."""
        self._service_checks_map[service].discard(check_name)
        self._completed_checks.add(check_name)
        self._findings.extend(findings)

        self._provider.audit_metadata = update_audit_metadata(
            self._provider.audit_metadata,
            self.remaining_services.keys(),
            self._completed_checks,
        )


def get_service_from_check(check_name: str) -> str:
    """
    Return the service name for a given check name.

    Example:
        get_service_from_check("ec2_instance_public") -> "ec2"
    """
    return check_name.split("_")[0]


def get_service_checks_mapping(checks: List[str]) -> Dict[str, Set[str]]:
    """
    Return a dictionary with the services and the checks to execute.

    Example:
        get_service_checks_mapping({"accessanalyzer_enabled", "ec2_instance_public_ip"})
        -> {"accessanalyzer": {"accessanalyzer_enabled"}, "ec2": {"ec2_instance_public_ip"}}
    """
    service_map = {}
    for check in checks:
        service = get_service_from_check(check)
        service_map.setdefault(service, set()).add(check)
    return service_map
