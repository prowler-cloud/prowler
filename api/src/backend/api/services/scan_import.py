"""
Scan Import Service for importing Prowler CLI scan results.

This module provides the ScanImportService class for importing external scan
results (JSON/OCSF and CSV formats) into the Prowler platform.

The service handles:
- Format detection and parsing
- Provider resolution or creation
- Bulk creation of resources, findings, and mappings
- Atomic transactions for data integrity

Example:
    >>> from api.services.scan_import import ScanImportService
    >>> service = ScanImportService(tenant_id="...")
    >>> result = service.import_scan(file_content, provider_id=None, create_provider=True)
    >>> print(f"Imported {result.findings_count} findings")
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from django.db import transaction

from api.db_utils import POSTGRES_TENANT_VAR, rls_transaction
from api.models import (
    Finding,
    Provider,
    Resource,
    ResourceFindingMapping,
    Scan,
    StateChoices,
)
from api.parsers import (
    CSVFinding,
    CSVParseError,
    OCSFFinding,
    OCSFParseError,
    parse_csv,
    parse_ocsf_json,
    validate_csv_structure,
    validate_ocsf_structure,
)

logger = logging.getLogger(__name__)

# Batch size for bulk operations
BULK_CREATE_BATCH_SIZE = 500

# Maximum file size (50MB)
MAX_FILE_SIZE = 50 * 1024 * 1024


class ScanImportError(Exception):
    """Exception raised when scan import fails."""

    def __init__(
        self,
        message: str,
        code: str = "import_error",
        details: dict[str, Any] | None = None,
    ):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "message": self.message,
            "code": self.code,
            "details": self.details,
        }


@dataclass
class ScanImportResult:
    """Result of a scan import operation."""

    scan_id: UUID
    provider_id: UUID
    findings_count: int
    resources_count: int
    provider_created: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "scan_id": str(self.scan_id),
            "provider_id": str(self.provider_id),
            "findings_count": self.findings_count,
            "resources_count": self.resources_count,
            "provider_created": self.provider_created,
            "warnings": self.warnings,
        }


# Type alias for parsed findings (either OCSF or CSV)
ParsedFinding = OCSFFinding | CSVFinding


class ScanImportService:
    """
    Service for importing Prowler scan results.

    Handles parsing, validation, and bulk database operations for importing
    external scan results into the Prowler platform.

    Attributes:
        tenant_id: UUID of the tenant performing the import.

    Example:
        >>> service = ScanImportService(tenant_id="550e8400-...")
        >>> result = service.import_scan(
        ...     file_content=json_bytes,
        ...     provider_id=None,
        ...     create_provider=True
        ... )
    """

    def __init__(self, tenant_id: str):
        """
        Initialize the scan import service.

        Args:
            tenant_id: UUID string of the tenant performing the import.
        """
        self.tenant_id = tenant_id

    def import_scan(
        self,
        file_content: bytes,
        provider_id: UUID | str | None = None,
        create_provider: bool = True,
    ) -> ScanImportResult:
        """
        Import scan results from file content.

        This is the main entry point for scan import. It handles:
        1. Format detection (JSON/OCSF or CSV)
        2. Content parsing and validation
        3. Provider resolution or creation
        4. Bulk creation of scan, resources, findings, and mappings

        All database operations are performed within a single atomic transaction
        to ensure data integrity.

        Args:
            file_content: Raw bytes of the scan file (JSON or CSV).
            provider_id: Optional UUID of existing provider to associate with.
            create_provider: If True, create provider if not found. Default True.

        Returns:
            ScanImportResult with scan ID, counts, and any warnings.

        Raises:
            ScanImportError: If import fails due to validation or processing errors.
        """
        # Validate file size
        if len(file_content) > MAX_FILE_SIZE:
            raise ScanImportError(
                message=f"File size exceeds maximum of {MAX_FILE_SIZE // (1024 * 1024)}MB",
                code="file_too_large",
                details={"size": len(file_content), "max_size": MAX_FILE_SIZE},
            )

        # Detect format and parse
        file_format = self._detect_format(file_content)
        findings = self._parse_content(file_content, file_format)

        if not findings:
            raise ScanImportError(
                message="No findings found in the imported file",
                code="no_findings",
            )

        # Convert provider_id to UUID if string
        if isinstance(provider_id, str):
            try:
                provider_id = UUID(provider_id)
            except ValueError:
                raise ScanImportError(
                    message="Invalid provider_id format",
                    code="invalid_provider_id",
                    details={"provider_id": provider_id},
                )

        # Perform import within RLS transaction
        with rls_transaction(value=self.tenant_id, parameter=POSTGRES_TENANT_VAR):
            with transaction.atomic():
                # Resolve or create provider
                provider, provider_created = self._resolve_provider(
                    findings=findings,
                    provider_id=provider_id,
                    create_provider=create_provider,
                )

                # Create scan record
                scan = self._create_scan(findings, provider)

                # Bulk create resources
                resources_map = self._bulk_create_resources(findings, provider)

                # Bulk create findings
                findings_count = self._bulk_create_findings(findings, scan, resources_map)

                # Update scan with resource count
                scan.unique_resource_count = len(resources_map)
                scan.save(update_fields=["unique_resource_count"])

        return ScanImportResult(
            scan_id=scan.id,
            provider_id=provider.id,
            findings_count=findings_count,
            resources_count=len(resources_map),
            provider_created=provider_created,
        )

    def _detect_format(self, content: bytes) -> str:
        """
        Detect the format of the file content.

        Attempts to validate content as JSON/OCSF first, then CSV.

        Args:
            content: Raw bytes to analyze.

        Returns:
            Format string: "json" or "csv".

        Raises:
            ScanImportError: If format cannot be determined.
        """
        # Try JSON/OCSF first
        is_valid_json, json_error = validate_ocsf_structure(content)
        if is_valid_json:
            return "json"

        # Try CSV
        is_valid_csv, csv_error = validate_csv_structure(content)
        if is_valid_csv:
            return "csv"

        # Neither format is valid
        raise ScanImportError(
            message="File format not recognized. Must be valid JSON/OCSF or CSV.",
            code="invalid_format",
            details={
                "json_error": json_error,
                "csv_error": csv_error,
            },
        )

    def _parse_content(
        self, content: bytes, file_format: str
    ) -> list[ParsedFinding]:
        """
        Parse file content based on detected format.

        Args:
            content: Raw bytes to parse.
            file_format: Format string ("json" or "csv").

        Returns:
            List of parsed findings.

        Raises:
            ScanImportError: If parsing fails.
        """
        try:
            if file_format == "json":
                return parse_ocsf_json(content)
            elif file_format == "csv":
                return parse_csv(content)
            else:
                raise ScanImportError(
                    message=f"Unsupported format: {file_format}",
                    code="unsupported_format",
                )
        except OCSFParseError as e:
            raise ScanImportError(
                message=f"Failed to parse JSON/OCSF: {e.message}",
                code="json_parse_error",
                details={"index": e.index, "field": e.field},
            )
        except CSVParseError as e:
            raise ScanImportError(
                message=f"Failed to parse CSV: {e.message}",
                code="csv_parse_error",
                details={"row": e.row, "column": e.column},
            )

    def _resolve_provider(
        self,
        findings: list[ParsedFinding],
        provider_id: UUID | None,
        create_provider: bool,
    ) -> tuple[Provider, bool]:
        """
        Find or create provider from findings data.

        Resolution order:
        1. If provider_id is given, use that provider
        2. Try to find existing provider by type and account UID
        3. If create_provider is True, create new provider
        4. Otherwise, raise error

        Args:
            findings: List of parsed findings to extract provider info from.
            provider_id: Optional UUID of existing provider.
            create_provider: Whether to create provider if not found.

        Returns:
            Tuple of (Provider instance, was_created boolean).

        Raises:
            ScanImportError: If provider cannot be resolved.
        """
        # If provider_id is specified, use it
        if provider_id:
            try:
                provider = Provider.objects.get(
                    id=provider_id,
                    tenant_id=self.tenant_id,
                )
                return provider, False
            except Provider.DoesNotExist:
                raise ScanImportError(
                    message=f"Provider with ID {provider_id} not found",
                    code="provider_not_found",
                    details={"provider_id": str(provider_id)},
                )

        # Extract provider info from findings
        first_finding = findings[0]
        provider_type = first_finding.provider_type.lower()
        account_uid = first_finding.account_uid

        # Get account name if available
        account_name = ""
        if isinstance(first_finding, OCSFFinding):
            account_name = first_finding.account_name
        elif isinstance(first_finding, CSVFinding):
            account_name = first_finding.account_name

        # Validate provider type
        valid_provider_types = [choice[0] for choice in Provider.ProviderChoices.choices]
        if provider_type not in valid_provider_types:
            raise ScanImportError(
                message=f"Unsupported provider type: {provider_type}",
                code="invalid_provider_type",
                details={
                    "provider_type": provider_type,
                    "supported_types": valid_provider_types,
                },
            )

        # Try to find existing provider
        try:
            provider = Provider.objects.get(
                tenant_id=self.tenant_id,
                provider=provider_type,
                uid=account_uid,
            )
            return provider, False
        except Provider.DoesNotExist:
            pass

        # Create new provider if allowed
        if not create_provider:
            raise ScanImportError(
                message=f"No provider found for {provider_type} account {account_uid}",
                code="provider_not_found",
                details={
                    "provider_type": provider_type,
                    "account_uid": account_uid,
                },
            )

        # Create new provider
        provider = Provider.objects.create(
            tenant_id=self.tenant_id,
            provider=provider_type,
            uid=account_uid,
            alias=account_name or None,
            connected=None,  # Unknown connection status for imported providers
        )
        logger.info(
            f"Created new provider {provider.id} for {provider_type}/{account_uid}"
        )
        return provider, True

    def _create_scan(
        self,
        findings: list[ParsedFinding],
        provider: Provider,
    ) -> Scan:
        """
        Create a scan record for the import.

        Args:
            findings: List of parsed findings to extract timestamps from.
            provider: Provider to associate the scan with.

        Returns:
            Created Scan instance.
        """
        # Extract timestamps from findings
        timestamps = []
        for finding in findings:
            if finding.timestamp:
                timestamps.append(finding.timestamp)

        # Determine scan timestamps
        now = datetime.now(timezone.utc)
        started_at = min(timestamps) if timestamps else now
        completed_at = max(timestamps) if timestamps else now

        # Calculate duration in seconds
        duration = int((completed_at - started_at).total_seconds())

        scan = Scan.objects.create(
            tenant_id=self.tenant_id,
            provider=provider,
            trigger=Scan.TriggerChoices.IMPORTED,
            state=StateChoices.COMPLETED,
            started_at=started_at,
            completed_at=completed_at,
            duration=duration,
            unique_resource_count=0,  # Will be updated after resource creation
            progress=100,
        )
        logger.info(f"Created scan {scan.id} for import")
        return scan

    def _bulk_create_resources(
        self,
        findings: list[ParsedFinding],
        provider: Provider,
    ) -> dict[str, Resource]:
        """
        Bulk create or update resources from findings.

        Extracts unique resources from findings and creates/updates them
        in the database using bulk operations.

        Args:
            findings: List of parsed findings containing resource data.
            provider: Provider to associate resources with.

        Returns:
            Dictionary mapping resource UID to Resource instance.
        """
        # Extract unique resources
        resources_data: dict[str, dict[str, Any]] = {}

        for finding in findings:
            if isinstance(finding, OCSFFinding):
                # OCSF findings can have multiple resources
                for resource in finding.resources:
                    if resource.uid not in resources_data:
                        resources_data[resource.uid] = {
                            "uid": resource.uid,
                            "name": resource.name or resource.uid,
                            "region": resource.region or "",
                            "service": resource.service or "",
                            "type": resource.type or "",
                        }
            elif isinstance(finding, CSVFinding):
                # CSV findings have a single resource
                resource = finding.resource
                if resource.uid not in resources_data:
                    resources_data[resource.uid] = {
                        "uid": resource.uid,
                        "name": resource.name or resource.uid,
                        "region": resource.region or "",
                        "service": resource.service or "",
                        "type": resource.type or "",
                    }

        if not resources_data:
            return {}

        # Get existing resources
        existing_resources = {
            r.uid: r
            for r in Resource.objects.filter(
                tenant_id=self.tenant_id,
                provider=provider,
                uid__in=resources_data.keys(),
            )
        }

        # Prepare resources to create
        resources_to_create = []
        for uid, data in resources_data.items():
            if uid not in existing_resources:
                resources_to_create.append(
                    Resource(
                        tenant_id=self.tenant_id,
                        provider=provider,
                        uid=data["uid"],
                        name=data["name"],
                        region=data["region"],
                        service=data["service"],
                        type=data["type"],
                    )
                )

        # Bulk create new resources
        if resources_to_create:
            created_resources = Resource.objects.bulk_create(
                resources_to_create,
                batch_size=BULK_CREATE_BATCH_SIZE,
            )
            for resource in created_resources:
                existing_resources[resource.uid] = resource

        logger.info(
            f"Created {len(resources_to_create)} new resources, "
            f"reused {len(existing_resources) - len(resources_to_create)} existing"
        )
        return existing_resources

    def _bulk_create_findings(
        self,
        findings: list[ParsedFinding],
        scan: Scan,
        resources_map: dict[str, Resource],
    ) -> int:
        """
        Bulk create findings with resource mappings.

        Args:
            findings: List of parsed findings to create.
            scan: Scan to associate findings with.
            resources_map: Dictionary mapping resource UID to Resource instance.

        Returns:
            Number of findings created.
        """
        finding_objects = []
        finding_resource_pairs: list[tuple[int, list[str]]] = []  # (finding_index, resource_uids)

        for idx, parsed_finding in enumerate(findings):
            # Build check metadata
            check_metadata = self._build_check_metadata(parsed_finding)

            # Get resource UIDs for this finding
            resource_uids = self._get_resource_uids(parsed_finding)

            # Build finding object
            finding = Finding(
                tenant_id=self.tenant_id,
                scan=scan,
                uid=parsed_finding.uid,
                check_id=parsed_finding.check_id,
                status=parsed_finding.status,
                status_extended=parsed_finding.status_extended or "",
                severity=parsed_finding.severity,
                impact=parsed_finding.severity,  # Use severity as impact
                impact_extended=self._get_impact_extended(parsed_finding),
                check_metadata=check_metadata,
                compliance=parsed_finding.compliance or {},
                raw_result=self._get_raw_result(parsed_finding),
                first_seen_at=parsed_finding.timestamp or datetime.now(timezone.utc),
                delta=Finding.DeltaChoices.NEW,
                muted=self._get_muted_status(parsed_finding),
            )

            # Set denormalized resource fields
            if resource_uids:
                resources = [resources_map[uid] for uid in resource_uids if uid in resources_map]
                if resources:
                    finding.resource_regions = list({r.region for r in resources if r.region})
                    finding.resource_services = list({r.service for r in resources if r.service})
                    finding.resource_types = list({r.type for r in resources if r.type})

            # Set categories from check metadata
            categories = check_metadata.get("categories", [])
            if categories:
                finding.categories = categories

            finding_objects.append(finding)
            finding_resource_pairs.append((idx, resource_uids))

        # Bulk create findings
        created_findings = Finding.objects.bulk_create(
            finding_objects,
            batch_size=BULK_CREATE_BATCH_SIZE,
        )

        # Create resource-finding mappings
        self._create_resource_finding_mappings(
            created_findings, finding_resource_pairs, resources_map
        )

        logger.info(f"Created {len(created_findings)} findings")
        return len(created_findings)

    def _create_resource_finding_mappings(
        self,
        findings: list[Finding],
        finding_resource_pairs: list[tuple[int, list[str]]],
        resources_map: dict[str, Resource],
    ) -> None:
        """
        Create resource-finding mappings in bulk.

        Args:
            findings: List of created Finding instances.
            finding_resource_pairs: List of (finding_index, resource_uids) tuples.
            resources_map: Dictionary mapping resource UID to Resource instance.
        """
        mappings = []

        for finding_idx, resource_uids in finding_resource_pairs:
            finding = findings[finding_idx]
            for uid in resource_uids:
                if uid in resources_map:
                    mappings.append(
                        ResourceFindingMapping(
                            tenant_id=self.tenant_id,
                            finding=finding,
                            resource=resources_map[uid],
                        )
                    )

        if mappings:
            ResourceFindingMapping.objects.bulk_create(
                mappings,
                batch_size=BULK_CREATE_BATCH_SIZE,
                ignore_conflicts=True,  # Handle potential duplicates
            )
            logger.info(f"Created {len(mappings)} resource-finding mappings")

    def _build_check_metadata(self, finding: ParsedFinding) -> dict[str, Any]:
        """
        Build check metadata dictionary from parsed finding.

        Args:
            finding: Parsed finding (OCSF or CSV).

        Returns:
            Dictionary containing check metadata.
        """
        if isinstance(finding, OCSFFinding):
            metadata = finding.check_metadata
            return {
                "title": metadata.title,
                "description": metadata.description,
                "risk": metadata.risk,
                "remediation": {
                    "description": metadata.remediation_description,
                    "references": metadata.remediation_references,
                },
                "categories": metadata.categories,
                "related_url": metadata.related_url,
            }
        elif isinstance(finding, CSVFinding):
            metadata = finding.check_metadata
            return {
                "title": metadata.title,
                "description": metadata.description,
                "risk": metadata.risk,
                "remediation": {
                    "description": metadata.remediation_description,
                    "url": metadata.remediation_url,
                    "cli": metadata.remediation_cli,
                    "terraform": metadata.remediation_terraform,
                    "nativeiac": metadata.remediation_nativeiac,
                    "other": metadata.remediation_other,
                },
                "categories": metadata.categories,
                "related_url": metadata.related_url,
                "additional_urls": metadata.additional_urls,
                "notes": metadata.notes,
            }
        return {}

    def _get_resource_uids(self, finding: ParsedFinding) -> list[str]:
        """
        Extract resource UIDs from a parsed finding.

        Args:
            finding: Parsed finding (OCSF or CSV).

        Returns:
            List of resource UID strings.
        """
        if isinstance(finding, OCSFFinding):
            return [r.uid for r in finding.resources]
        elif isinstance(finding, CSVFinding):
            return [finding.resource.uid]
        return []

    def _get_impact_extended(self, finding: ParsedFinding) -> str:
        """
        Get impact extended text from parsed finding.

        Args:
            finding: Parsed finding (OCSF or CSV).

        Returns:
            Impact extended string.
        """
        if isinstance(finding, OCSFFinding):
            return finding.impact_extended or finding.message or ""
        elif isinstance(finding, CSVFinding):
            return finding.status_extended or ""
        return ""

    def _get_raw_result(self, finding: ParsedFinding) -> dict[str, Any]:
        """
        Get raw result data from parsed finding.

        Args:
            finding: Parsed finding (OCSF or CSV).

        Returns:
            Dictionary containing raw result data.
        """
        if isinstance(finding, OCSFFinding):
            return finding.raw_result
        elif isinstance(finding, CSVFinding):
            return finding.raw_row
        return {}

    def _get_muted_status(self, finding: ParsedFinding) -> bool:
        """
        Get muted status from parsed finding.

        Args:
            finding: Parsed finding (OCSF or CSV).

        Returns:
            Boolean indicating if finding is muted.
        """
        if isinstance(finding, CSVFinding):
            return finding.muted
        return False
