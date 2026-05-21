from csv import DictWriter
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from pydantic.v1 import create_model

from prowler.config.config import timestamp
from prowler.lib.check.compliance_models import ComplianceFramework
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file

if TYPE_CHECKING:
    from prowler.lib.outputs.finding import Finding

PROVIDER_HEADER_MAP = {
    "aws": ("AccountId", "account_uid", "Region", "region"),
    "azure": ("SubscriptionId", "account_uid", "Location", "region"),
    "gcp": ("ProjectId", "account_uid", "Location", "region"),
    "kubernetes": ("Context", "account_name", "Namespace", "region"),
    "m365": ("TenantId", "account_uid", "Location", "region"),
    "github": ("Account_Name", "account_name", "Account_Id", "account_uid"),
    "oraclecloud": ("TenancyId", "account_uid", "Region", "region"),
    "alibabacloud": ("AccountId", "account_uid", "Region", "region"),
    "nhn": ("AccountId", "account_uid", "Region", "region"),
}
_DEFAULT_HEADERS = ("AccountId", "account_uid", "Region", "region")


class UniversalComplianceOutput:
    """Universal compliance CSV output driven by ComplianceFramework metadata.

    Dynamically builds a Pydantic row model from attributes_metadata so that
    CSV columns match the framework's declared attribute fields.
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

        if file_path:
            path_obj = Path(file_path)
            self._file_extension = path_obj.suffix if path_obj.suffix else ""

        if findings:
            self._row_model = self._build_row_model(framework)
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

    def _build_row_model(self, framework: ComplianceFramework):
        """Build a dynamic Pydantic model from attributes_metadata."""
        acct_header, acct_field, loc_header, loc_field = PROVIDER_HEADER_MAP.get(
            (self._provider or "").lower(), _DEFAULT_HEADERS
        )
        self._acct_header = acct_header
        self._acct_field = acct_field
        self._loc_header = loc_header
        self._loc_field = loc_field

        # Base fields present in every compliance CSV
        fields = {
            "Provider": (str, ...),
            "Description": (str, ...),
            acct_header: (str, ...),
            loc_header: (str, ...),
            "AssessmentDate": (str, ...),
            "Requirements_Id": (str, ...),
            "Requirements_Description": (str, ...),
        }

        # Dynamic attribute columns from metadata
        if framework.attributes_metadata:
            for attr_meta in framework.attributes_metadata:
                if not attr_meta.output_formats.csv:
                    continue
                field_name = f"Requirements_Attributes_{attr_meta.key}"
                # Map type strings to Python types
                type_map = {
                    "str": Optional[str],
                    "int": Optional[int],
                    "float": Optional[float],
                    "bool": Optional[bool],
                    "list_str": Optional[str],  # Serialized as joined string
                    "list_dict": Optional[str],  # Serialized as string
                }
                py_type = type_map.get(attr_meta.type, Optional[str])
                fields[field_name] = (py_type, None)

        # Check if any requirement has MITRE fields
        has_mitre = any(req.tactics for req in framework.requirements if req.tactics)
        if has_mitre:
            fields["Requirements_Tactics"] = (Optional[str], None)
            fields["Requirements_SubTechniques"] = (Optional[str], None)
            fields["Requirements_Platforms"] = (Optional[str], None)
            fields["Requirements_TechniqueURL"] = (Optional[str], None)

        # Trailing fields
        fields["Status"] = (str, ...)
        fields["StatusExtended"] = (str, ...)
        fields["ResourceId"] = (str, ...)
        fields["ResourceName"] = (str, ...)
        fields["CheckId"] = (str, ...)
        fields["Muted"] = (bool, ...)
        fields["Framework"] = (str, ...)
        fields["Name"] = (str, ...)

        return create_model("UniversalComplianceRow", **fields)

    def _serialize_attr_value(self, value):
        """Serialize attribute values for CSV."""
        if isinstance(value, list):
            if value and isinstance(value[0], dict):
                return str(value)
            return " | ".join(str(v) for v in value)
        return value

    def _build_row(self, finding, framework, requirement, is_manual=False):
        """Build a single row dict for a finding + requirement combination."""
        row = {
            "Provider": (
                finding.provider
                if not is_manual
                else (framework.provider or self._provider or "").lower()
            ),
            "Description": framework.description,
            self._acct_header: (
                getattr(finding, self._acct_field, "") if not is_manual else ""
            ),
            self._loc_header: (
                getattr(finding, self._loc_field, "") if not is_manual else ""
            ),
            "AssessmentDate": str(timestamp),
            "Requirements_Id": requirement.id,
            "Requirements_Description": requirement.description,
        }

        # Add dynamic attribute columns
        if framework.attributes_metadata:
            for attr_meta in framework.attributes_metadata:
                if not attr_meta.output_formats.csv:
                    continue
                field_name = f"Requirements_Attributes_{attr_meta.key}"
                raw_val = requirement.attributes.get(attr_meta.key)
                row[field_name] = (
                    self._serialize_attr_value(raw_val) if raw_val is not None else None
                )

        # MITRE fields
        if requirement.tactics:
            row["Requirements_Tactics"] = (
                " | ".join(requirement.tactics) if requirement.tactics else None
            )
            row["Requirements_SubTechniques"] = (
                " | ".join(requirement.sub_techniques)
                if requirement.sub_techniques
                else None
            )
            row["Requirements_Platforms"] = (
                " | ".join(requirement.platforms) if requirement.platforms else None
            )
            row["Requirements_TechniqueURL"] = requirement.technique_url

        row["Status"] = finding.status if not is_manual else "MANUAL"
        row["StatusExtended"] = (
            finding.status_extended if not is_manual else "Manual check"
        )
        row["ResourceId"] = finding.resource_uid if not is_manual else "manual_check"
        row["ResourceName"] = finding.resource_name if not is_manual else "Manual check"
        row["CheckId"] = finding.check_id if not is_manual else "manual"
        row["Muted"] = finding.muted if not is_manual else False
        row["Framework"] = framework.framework
        row["Name"] = framework.name

        return row

    def _transform(
        self,
        findings: list["Finding"],
        framework: ComplianceFramework,
        compliance_name: str,
    ) -> None:
        """Transform findings into universal compliance CSV rows."""
        # Build check -> requirements map (filtered by provider for dict checks)
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
                if check_id not in check_req_map:
                    check_req_map[check_id] = []
                check_req_map[check_id].append(req)

        # Process findings using the provider-filtered check_req_map.
        # This ensures that for multi-provider dict checks, only the checks
        # belonging to the current provider produce output rows.
        for finding in findings:
            check_id = finding.check_id
            if check_id in check_req_map:
                for req in check_req_map[check_id]:
                    row = self._build_row(finding, framework, req)
                    try:
                        self._data.append(self._row_model(**row))
                    except Exception as e:
                        logger.debug(f"Skipping row for {req.id}: {e}")

        # Manual requirements (no checks or empty dict)
        for req in framework.requirements:
            checks = req.checks
            if self._provider:
                has_checks = bool(checks.get(self._provider.lower(), []))
            else:
                has_checks = any(checks.values())

            if not has_checks:
                # Use a dummy finding-like namespace for manual rows
                row = self._build_row(
                    _ManualFindingStub(), framework, req, is_manual=True
                )
                try:
                    self._data.append(self._row_model(**row))
                except Exception as e:
                    logger.debug(f"Skipping manual row for {req.id}: {e}")

    def _create_file_descriptor(self, file_path: str) -> None:
        try:
            self._file_descriptor = open_file(file_path, "a")
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self) -> None:
        """Write findings data to CSV."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                csv_writer = DictWriter(
                    self._file_descriptor,
                    fieldnames=[field.upper() for field in self._data[0].dict().keys()],
                    delimiter=";",
                )
                if self._file_descriptor.tell() == 0:
                    csv_writer.writeheader()
                for row in self._data:
                    csv_writer.writerow({k.upper(): v for k, v in row.dict().items()})
                if self.close_file or self._from_cli:
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class _ManualFindingStub:
    """Minimal stub to satisfy _build_row for manual requirements."""

    provider = ""
    account_uid = ""
    account_name = ""
    region = ""
    status = "MANUAL"
    status_extended = "Manual check"
    resource_uid = "manual_check"
    resource_name = "Manual check"
    check_id = "manual"
    muted = False
