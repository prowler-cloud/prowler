from csv import DictWriter
from typing import Any

from prowler.lib.outputs.common_models import FindingOutput
from prowler.lib.outputs.csv.models import CSVOutput, CSVRow


def write_csv(file_descriptor, headers, row):
    csv_writer = DictWriter(
        file_descriptor,
        fieldnames=headers,
        delimiter=";",
    )
    csv_writer.writerow(row.__dict__)


def generate_csv_fields(format: Any) -> list[str]:
    """Generates the CSV headers for the given class"""
    csv_fields = []
    # __fields__ is always available in the Pydantic's BaseModel class
    for field in format.__dict__.get("__fields__").keys():
        csv_fields.append(field)
    return csv_fields


def generate_csv(findings: list[FindingOutput], file_descriptor) -> CSVOutput:
    """Generates the CSV output for the given findings"""
    csv_output = CSVOutput(findings=[])
    csv_output.findings = []
    for finding in findings:
        csv_row = CSVRow(
            auth_method=finding.auth_method,
            timestamp=finding.timestamp,
            account_uid=finding.account_uid,
            account_name=finding.account_name,
            account_email=finding.account_email,
            account_organization_uid=finding.account_organization_uid,
            account_organization=finding.account_organization_name,
            account_tags=finding.account_tags,
            finding_uid=finding.finding_uid,
            provider=finding.provider,
            check_id=finding.check_id,
            check_title=finding.check_title,
            check_type=finding.check_type,
            status=finding.status,
            status_extended=finding.status_extended,
            muted=finding.muted,
            service_name=finding.service_name,
            subservice_name=finding.subservice_name,
            severity=finding.severity,
            resource_type=finding.resource_type,
            resource_uid=finding.resource_uid,
            resource_name=finding.resource_name,
            resource_details=finding.resource_details,
            resource_tags=finding.resource_tags,
            partition=finding.partition,
            region=finding.region,
            description=finding.description,
            risk=finding.risk,
            related_url=finding.related_url,
            remediation_recommendation_text=finding.remediation_recommendation_text,
            remediation_recommendation_url=finding.remediation_recommendation_url,
            remediation_code_nativeiac=finding.remediation_code_nativeiac,
            remediation_code_terraform=finding.remediation_code_terraform,
            remediation_code_cli=finding.remediation_code_cli,
            remediation_code_other=finding.remediation_code_other,
            compliance=finding.compliance,
            categories=finding.categories,
            depends_on=finding.depends_on,
            related_to=finding.related_to,
            notes=finding.notes,
        )
        csv_output.findings.append(csv_row)

    return csv_output
