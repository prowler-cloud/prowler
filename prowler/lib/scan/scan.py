import datetime
from types import SimpleNamespace
from typing import Generator

from alive_progress import alive_bar

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
from prowler.lib.scan.exceptions.exceptions import (
    ScanInvalidCategoryError,
    ScanInvalidCheckError,
    ScanInvalidComplianceFrameworkError,
    ScanInvalidServiceError,
    ScanInvalidSeverityError,
    ScanInvalidStatusError,
)
from prowler.providers.common.models import Audit_Metadata, ProviderOutputOptions
from prowler.providers.common.provider import Provider


class Scan:
    _provider: Provider
    # Refactor(Core): This should replace the Audit_Metadata
    _number_of_checks_to_execute: int = 0
    _number_of_checks_completed: int = 0
    # TODO the str should be a set of Check objects
    _checks_to_execute: list[str]
    _service_checks_to_execute: dict[str, set[str]]
    _service_checks_completed: dict[str, set[str]]
    _progress: float = 0.0
    _duration: int = 0
    _status: list[str] = None
    _bulk_checks_metadata: dict[str, CheckMetadata]
    _bulk_compliance_frameworks: dict
    _enrich_findings: bool = False
    _enrichment_config: dict = None
    _enricher = None

    def __init__(
        self,
        provider: Provider,
        checks: list[str] = None,
        services: list[str] = None,
        compliances: list[str] = None,
        categories: list[str] = None,
        severities: list[str] = None,
        excluded_checks: list[str] = None,
        excluded_services: list[str] = None,
        status: list[str] = None,
        enrich_findings: bool = False,
        enrichment_config: dict = None,
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
            enrich_findings: bool -> Enable CloudTrail enrichment (AWS only)
            enrichment_config: dict -> Enrichment configuration (lookback_days, max_events, severities)

        Raises:
            ScanInvalidCheckError: If the check does not exist in the provider or is from another provider.
            ScanInvalidServiceError: If the service does not exist in the provider.
            ScanInvalidComplianceFrameworkError: If the compliance framework does not exist in the provider.
            ScanInvalidCategoryError: If the category does not exist in the provider.
            ScanInvalidSeverityError: If the severity does not exist in the provider.
            ScanInvalidStatusError: If the status does not exist in the provider.
        """
        self._provider = provider

        # Validate the status
        if status:
            try:
                for s in status:
                    Status(s)
                    if not self._status:
                        self._status = []
                    if s not in self._status:
                        self._status.append(s)
            except ValueError:
                raise ScanInvalidStatusError(f"Invalid status provided: {s}.")

        # Load bulk compliance frameworks
        self._bulk_compliance_frameworks = Compliance.get_bulk(provider.type)

        # Get bulk checks metadata for the provider
        self._bulk_checks_metadata = CheckMetadata.get_bulk(provider.type)
        # Complete checks metadata with the compliance framework specification
        self._bulk_checks_metadata = update_checks_metadata_with_compliance(
            self._bulk_compliance_frameworks, self._bulk_checks_metadata
        )

        # Create a list of valid categories
        valid_categories = set()
        for check, metadata in self._bulk_checks_metadata.items():
            for category in metadata.Categories:
                if category not in valid_categories:
                    valid_categories.add(category)

        # Validate checks
        if checks:
            for check in checks:
                if check not in self._bulk_checks_metadata.keys():
                    raise ScanInvalidCheckError(f"Invalid check provided: {check}.")

        # Validate services
        if services:
            for service in services:
                if service not in list_services(provider.type):
                    raise ScanInvalidServiceError(
                        f"Invalid service provided: {service}."
                    )

        # Validate compliances
        if compliances:
            for compliance in compliances:
                if compliance not in self._bulk_compliance_frameworks.keys():
                    raise ScanInvalidComplianceFrameworkError(
                        f"Invalid compliance provided: {compliance}."
                    )

        # Validate categories
        if categories:
            for category in categories:
                if category not in valid_categories:
                    raise ScanInvalidCategoryError(
                        f"Invalid category provided: {category}."
                    )

        # Validate severity
        if severities:
            for severity in severities:
                try:
                    Severity(severity)
                except ValueError:
                    raise ScanInvalidSeverityError(
                        f"Invalid severity provided: {severity}."
                    )

        # Load checks to execute
        self._checks_to_execute = sorted(
            load_checks_to_execute(
                bulk_checks_metadata=self._bulk_checks_metadata,
                bulk_compliance_frameworks=self._bulk_compliance_frameworks,
                check_list=checks,
                service_list=services,
                compliance_frameworks=compliances,
                categories=categories,
                severities=severities,
                provider=provider.type,
                checks_file=None,
            )
        )

        # Exclude checks
        if excluded_checks:
            for check in excluded_checks:
                if check in self._checks_to_execute:
                    self._checks_to_execute.remove(check)
                else:
                    raise ScanInvalidCheckError(
                        f"Invalid check provided: {check}. Check does not exist in the provider."
                    )

        # Exclude services
        if excluded_services:
            for check in self._checks_to_execute:
                if get_service_name_from_check_name(check) in excluded_services:
                    self._checks_to_execute.remove(check)
                else:
                    raise ScanInvalidServiceError(
                        f"Invalid service provided: {check}. Service does not exist in the provider."
                    )

        self._number_of_checks_to_execute = len(self._checks_to_execute)

        service_checks_to_execute = get_service_checks_to_execute(
            self._checks_to_execute
        )
        service_checks_completed = dict()

        self._service_checks_to_execute = service_checks_to_execute
        self._service_checks_completed = service_checks_completed

        # Store enrichment configuration
        self._enrich_findings = enrich_findings
        self._enrichment_config = enrichment_config or {}

    @property
    def checks_to_execute(self) -> list[str]:
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
    def bulk_checks_metadata(self) -> dict[str, CheckMetadata]:
        return self._bulk_checks_metadata

    @property
    def bulk_compliance_frameworks(self) -> dict[str, CheckMetadata]:
        return self._bulk_compliance_frameworks

    def scan(
        self,
        custom_checks_metadata: dict = None,
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
            # Using SimpleNamespace to create a mocked object
            arguments = SimpleNamespace()

            output_options = ProviderOutputOptions(
                arguments=arguments,
                bulk_checks_metadata=self.bulk_checks_metadata,
            )

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

            # Track all findings for post-scan enrichment
            all_findings_for_enrichment = []

            for check_name in checks_to_execute:
                try:
                    # Recover service from check name
                    service = get_service_name_from_check_name(check_name)
                    try:
                        # Map CLI provider names to directory names (for cases where they differ)
                        provider_directory_map = {
                            "oci": "oraclecloud",  # OCI SDK conflict avoidance
                        }
                        provider_directory = provider_directory_map.get(
                            self._provider.type, self._provider.type
                        )

                        # Import check module
                        check_module_path = f"prowler.providers.{provider_directory}.services.{service}.{check_name}.{check_name}"
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

                    # Filter the findings by the status
                    if self._status:
                        for finding in check_findings:
                            if finding.status not in self._status:
                                check_findings.remove(finding)

                    # Store findings for post-scan enrichment
                    if self._enrich_findings and check_findings:
                        all_findings_for_enrichment.extend(check_findings)

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

                    findings = []
                    for finding in check_findings:
                        try:
                            findings.append(
                                Finding.generate_output(
                                    self.provider,
                                    finding,
                                    output_options=output_options,
                                )
                            )
                        except Exception:
                            continue

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

            # Post-scan enrichment (if enabled)
            if self._enrich_findings and all_findings_for_enrichment:
                enrichment_stats = self._enrich_findings_post_scan(
                    all_findings_for_enrichment
                )
                # Show enrichment summary
                if enrichment_stats:
                    total_enriched = enrichment_stats["total_enriched"]
                    total_checked = enrichment_stats["total_checked"]
                    if total_checked > 0:
                        enrichment_percentage = (total_enriched / total_checked) * 100
                        logger.info("\nCloudTrail Enrichment Summary:")
                        logger.info(
                            f"  ✨ Enriched {total_enriched}/{total_checked} findings ({enrichment_percentage:.1f}%)"
                        )

        except Exception as error:
            logger.error(
                f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _enrich_findings_post_scan(self, findings: list[Finding]) -> dict:
        """
        Enriches findings after scan completes using CloudTrail events.
        Deduplicates resources to avoid redundant API calls.

        Args:
            findings: List of all findings from the scan

        Returns:
            dict: Statistics about enrichment (total_enriched, total_checked)
        """
        if self._provider.type != "aws":
            logger.warning(
                "CloudTrail enrichment is only available for AWS provider. Skipping enrichment."
            )
            return {"total_enriched": 0, "total_checked": 0}

        try:
            from prowler.providers.aws.services.cloudtrail.lib.enrichment.cloudtrail_enricher import (
                CloudTrailEnricher,
            )

            logger.info("\nStarting CloudTrail enrichment...")

            lookback_days = self._enrichment_config.get("lookback_days", 90)
            enrich_severities = self._enrichment_config.get("severities", None)

            # Initialize enricher
            enricher = CloudTrailEnricher(
                lookback_days=lookback_days,
            )

            # Deduplicate resources: group findings by resource_id
            resource_findings_map = {}  # {resource_id: [(finding, region), ...]}

            for finding in findings:
                # Apply severity filter
                if enrich_severities:
                    severity = finding.check_metadata.get("Severity")
                    if severity not in enrich_severities:
                        continue

                resource_id = finding.resource_id
                region = finding.region

                if resource_id not in resource_findings_map:
                    resource_findings_map[resource_id] = []
                resource_findings_map[resource_id].append((finding, region))

            # Enrich each unique resource once using correct regional client
            enrichment_cache = {}  # {resource_id: enrichment_data}
            total_checked = len(resource_findings_map)
            total_enriched = 0

            # Use progress bar for enrichment
            with alive_bar(
                total_checked,
                ctrl_c=False,
                bar="smooth",
                spinner="dots_waves",
                title=f"-> Enriching {total_checked} unique resources",
            ) as bar:
                for resource_id, finding_list in resource_findings_map.items():
                    # Get first finding with this resource
                    first_finding, _ = finding_list[0]

                    try:
                        # Enrich the finding
                        enrichment = enricher.enrich_finding(first_finding)

                        if enrichment:
                            enrichment_cache[resource_id] = enrichment
                            total_enriched += 1

                    except Exception as e:
                        logger.info(f"Could not enrich resource {resource_id}: {e}")

                    bar()

            # Apply enrichment to all findings with the same resource
            for resource_id, enrichment_data in enrichment_cache.items():
                if resource_id in resource_findings_map:
                    for finding, _ in resource_findings_map[resource_id]:
                        finding.enrichment = enrichment_data

            return {"total_enriched": total_enriched, "total_checked": total_checked}

        except ImportError as e:
            logger.error(f"Failed to import CloudTrail enricher: {e}")
            return {"total_enriched": 0, "total_checked": 0}
        except Exception as e:
            logger.error(f"Failed to enrich findings: {e}")
            return {"total_enriched": 0, "total_checked": 0}

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
