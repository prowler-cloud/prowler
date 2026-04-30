import json
import os
from datetime import datetime
from typing import TYPE_CHECKING, List

from py_ocsf_models.events.base_event import SeverityID
from py_ocsf_models.events.base_event import StatusID as EventStatusID
from py_ocsf_models.events.findings.compliance_finding import ComplianceFinding
from py_ocsf_models.events.findings.compliance_finding_type_id import (
    ComplianceFindingTypeID,
)
from py_ocsf_models.events.findings.finding import ActivityID, FindingInformation
from py_ocsf_models.objects.check import Check
from py_ocsf_models.objects.compliance import Compliance
from py_ocsf_models.objects.compliance_status import StatusID as ComplianceStatusID
from py_ocsf_models.objects.group import Group
from py_ocsf_models.objects.metadata import Metadata
from py_ocsf_models.objects.product import Product
from py_ocsf_models.objects.resource_details import ResourceDetails

from prowler.config.config import prowler_version
from prowler.lib.check.compliance_models import ComplianceFramework
from prowler.lib.logger import logger
from prowler.lib.outputs.utils import unroll_dict_to_list
from prowler.lib.utils.utils import open_file

if TYPE_CHECKING:
    from prowler.lib.outputs.finding import Finding

PROWLER_TO_COMPLIANCE_STATUS = {
    "PASS": ComplianceStatusID.Pass,
    "FAIL": ComplianceStatusID.Fail,
    "MANUAL": ComplianceStatusID.Unknown,
}


def _sanitize_resource_data(resource_details, resource_metadata) -> dict:
    """Ensure resource data is JSON-serializable.

    Service resource_metadata may carry non-serializable objects (e.g. raw
    Pydantic models or service classes such as ``Trail`` / ``LifecyclePolicy``).
    Convert them to plain dicts and roundtrip through JSON so the resulting
    ComplianceFinding can be serialized without errors.
    """

    def _make_serializable(obj):
        if hasattr(obj, "model_dump") and callable(obj.model_dump):
            return _make_serializable(obj.model_dump())
        if hasattr(obj, "dict") and callable(obj.dict):
            return _make_serializable(obj.dict())
        if isinstance(obj, dict):
            return {str(k): _make_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_make_serializable(v) for v in obj]
        return obj

    try:
        converted = _make_serializable(resource_metadata)
        sanitized_metadata = json.loads(json.dumps(converted, default=str))
    except (TypeError, ValueError) as error:
        logger.warning(
            f"Failed to serialize resource metadata, defaulting to empty: {error}"
        )
        sanitized_metadata = {}
    return {
        "details": resource_details,
        "metadata": sanitized_metadata,
    }


def _to_snake_case(name: str) -> str:
    """Convert a PascalCase or camelCase string to snake_case."""
    import re

    # Insert underscore before uppercase letters preceded by lowercase
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    # Insert underscore between consecutive uppercase and following lowercase
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return s.lower()


def _build_requirement_attrs(requirement, framework) -> dict:
    """Build a dict with requirement attributes for the unmapped section.

    Keys are normalized to snake_case for OCSF consistency.
    Only includes attributes whose AttributeMetadata has output_formats.ocsf=True.
    When no metadata is declared, all attributes are included.
    """
    attrs = requirement.attributes
    if not attrs:
        return {}

    # Build set of keys allowed for OCSF output
    metadata = framework.attributes_metadata
    if metadata:
        ocsf_keys = {m.key for m in metadata if m.output_formats.ocsf}
    else:
        ocsf_keys = None  # No metadata → include all

    result = {}
    for key, value in attrs.items():
        if ocsf_keys is not None and key not in ocsf_keys:
            continue
        result[_to_snake_case(key)] = value
    return result


class OCSFComplianceOutput:
    """Produces OCSF ComplianceFinding (class_uid 2003) events from
    universal compliance framework data.

    Each finding × requirement combination produces one ComplianceFinding event
    with structured Compliance and Check objects.
    """

    def __init__(
        self,
        findings: list,
        framework: ComplianceFramework,
        file_path: str = None,
        from_cli: bool = True,
        provider: str = None,
    ) -> None:
        self._data = []
        self._file_descriptor = None
        self.file_path = file_path
        self._from_cli = from_cli
        self._provider = provider
        self.close_file = False

        if findings:
            compliance_name = (
                framework.framework + "-" + framework.version
                if framework.version
                else framework.framework
            )
            self._transform(findings, framework, compliance_name)
            if not self._file_descriptor and file_path:
                self._create_file_descriptor(file_path)

    @property
    def data(self):
        return self._data

    def _transform(
        self,
        findings: List["Finding"],
        framework: ComplianceFramework,
        compliance_name: str,
    ) -> None:
        # Build check -> requirements map
        check_req_map = {}
        for req in framework.requirements:
            checks = req.checks
            if self._provider:
                all_checks = checks.get(self._provider.lower(), [])
            else:
                all_checks = []
                for check_list in checks.values():
                    all_checks.extend(check_list)
            for check_id in all_checks:
                check_req_map.setdefault(check_id, []).append(req)

        for finding in findings:
            if finding.check_id in check_req_map:
                for req in check_req_map[finding.check_id]:
                    cf = self._build_compliance_finding(
                        finding, framework, req, compliance_name
                    )
                    if cf:
                        self._data.append(cf)

        # Manual requirements (no checks or empty for current provider)
        for req in framework.requirements:
            checks = req.checks
            if self._provider:
                has_checks = bool(checks.get(self._provider.lower(), []))
            else:
                has_checks = any(checks.values())

            if not has_checks:
                cf = self._build_manual_compliance_finding(
                    framework, req, compliance_name
                )
                if cf:
                    self._data.append(cf)

    def _build_unmapped(self, finding, requirement, framework) -> dict:
        """Build the unmapped dict with cloud info and requirement attributes."""
        unmapped = {}

        # Cloud info (from finding, when available)
        if finding and getattr(finding, "provider", None) != "kubernetes":
            unmapped["cloud"] = {
                "provider": finding.provider,
                "region": finding.region,
                "account": {
                    "uid": finding.account_uid,
                    "name": finding.account_name,
                },
                "org": {
                    "uid": finding.account_organization_uid,
                    "name": finding.account_organization_name,
                },
            }

        # Requirement attributes
        req_attrs = _build_requirement_attrs(requirement, framework)
        if req_attrs:
            unmapped["requirement_attributes"] = req_attrs

        return unmapped or None

    def _build_compliance_finding(
        self,
        finding: "Finding",
        framework: ComplianceFramework,
        requirement,
        compliance_name: str,
    ) -> ComplianceFinding:
        try:
            compliance_status = PROWLER_TO_COMPLIANCE_STATUS.get(
                finding.status, ComplianceStatusID.Unknown
            )
            check_status = PROWLER_TO_COMPLIANCE_STATUS.get(
                finding.status, ComplianceStatusID.Unknown
            )

            finding_severity = getattr(
                SeverityID,
                finding.metadata.Severity.capitalize(),
                SeverityID.Unknown,
            )
            event_status = (
                EventStatusID.Suppressed if finding.muted else EventStatusID.New
            )

            time_value = (
                int(finding.timestamp.timestamp())
                if isinstance(finding.timestamp, datetime)
                else finding.timestamp
            )

            cf = ComplianceFinding(
                activity_id=ActivityID.Create.value,
                activity_name=ActivityID.Create.name,
                compliance=Compliance(
                    standards=[compliance_name],
                    requirements=[requirement.id],
                    control=requirement.description,
                    status_id=compliance_status,
                    checks=[
                        Check(
                            uid=finding.check_id,
                            name=finding.metadata.CheckTitle,
                            desc=finding.metadata.Description,
                            status=finding.status,
                            status_id=check_status,
                        )
                    ],
                ),
                finding_info=FindingInformation(
                    uid=f"{finding.uid}-{requirement.id}",
                    title=requirement.id,
                    desc=requirement.description,
                    created_time=time_value,
                    created_time_dt=(
                        finding.timestamp
                        if isinstance(finding.timestamp, datetime)
                        else None
                    ),
                ),
                message=finding.status_extended,
                metadata=Metadata(
                    event_code=finding.check_id,
                    product=Product(
                        uid="prowler",
                        name="Prowler",
                        vendor_name="Prowler",
                        version=finding.prowler_version,
                    ),
                    profiles=(
                        ["cloud", "datetime"]
                        if finding.provider != "kubernetes"
                        else ["container", "datetime"]
                    ),
                    tenant_uid=finding.account_organization_uid,
                ),
                resources=[
                    ResourceDetails(
                        labels=unroll_dict_to_list(finding.resource_tags),
                        name=finding.resource_name,
                        uid=finding.resource_uid,
                        group=Group(name=finding.metadata.ServiceName),
                        type=finding.metadata.ResourceType,
                        cloud_partition=(
                            finding.partition
                            if finding.provider != "kubernetes"
                            else None
                        ),
                        region=(
                            finding.region if finding.provider != "kubernetes" else None
                        ),
                        namespace=(
                            finding.region.replace("namespace: ", "")
                            if finding.provider == "kubernetes"
                            else None
                        ),
                        data=_sanitize_resource_data(
                            finding.resource_details,
                            finding.resource_metadata,
                        ),
                    )
                ],
                severity_id=finding_severity.value,
                severity=finding_severity.name,
                status_id=event_status.value,
                status=event_status.name,
                status_code=finding.status,
                status_detail=finding.status_extended,
                time=time_value,
                time_dt=(
                    finding.timestamp
                    if isinstance(finding.timestamp, datetime)
                    else None
                ),
                type_uid=ComplianceFindingTypeID.Create,
                type_name=f"Compliance Finding: {ComplianceFindingTypeID.Create.name}",
                unmapped=self._build_unmapped(finding, requirement, framework),
            )

            return cf
        except Exception as e:
            logger.debug(f"Skipping OCSF compliance finding for {requirement.id}: {e}")
            return None

    def _build_manual_compliance_finding(
        self,
        framework: ComplianceFramework,
        requirement,
        compliance_name: str,
    ) -> ComplianceFinding:
        try:
            from prowler.config.config import timestamp as config_timestamp

            time_value = int(config_timestamp.timestamp())

            return ComplianceFinding(
                activity_id=ActivityID.Create.value,
                activity_name=ActivityID.Create.name,
                compliance=Compliance(
                    standards=[compliance_name],
                    requirements=[requirement.id],
                    control=requirement.description,
                    status_id=ComplianceStatusID.Unknown,
                ),
                finding_info=FindingInformation(
                    uid=f"manual-{requirement.id}",
                    title=requirement.id,
                    desc=requirement.description,
                    created_time=time_value,
                ),
                message="Manual check",
                metadata=Metadata(
                    event_code="manual",
                    product=Product(
                        uid="prowler",
                        name="Prowler",
                        vendor_name="Prowler",
                        version=prowler_version,
                    ),
                ),
                severity_id=SeverityID.Informational.value,
                severity=SeverityID.Informational.name,
                status_id=EventStatusID.New.value,
                status=EventStatusID.New.name,
                status_code="MANUAL",
                status_detail="Manual check",
                time=time_value,
                type_uid=ComplianceFindingTypeID.Create,
                type_name=f"Compliance Finding: {ComplianceFindingTypeID.Create.name}",
                unmapped=self._build_unmapped(None, requirement, framework),
            )
        except Exception as e:
            logger.debug(
                f"Skipping manual OCSF compliance finding for {requirement.id}: {e}"
            )
            return None

    def _create_file_descriptor(self, file_path: str) -> None:
        try:
            self._file_descriptor = open_file(file_path, "a")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self) -> None:
        """Write ComplianceFinding events to a JSON array file."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                if self._file_descriptor.tell() == 0:
                    self._file_descriptor.write("[")
                for finding in self._data:
                    try:
                        if hasattr(finding, "model_dump_json"):
                            json_output = finding.model_dump_json(
                                exclude_none=True, indent=4
                            )
                        else:
                            json_output = finding.json(exclude_none=True, indent=4)
                        self._file_descriptor.write(json_output)
                        self._file_descriptor.write(",")
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                if self.close_file or self._from_cli:
                    if self._file_descriptor.tell() != 1:
                        self._file_descriptor.seek(
                            self._file_descriptor.tell() - 1, os.SEEK_SET
                        )
                    self._file_descriptor.truncate()
                    self._file_descriptor.write("]")
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
