from csv import DictWriter
from venv import logger

from prowler.lib.check.compliance_models import ComplianceBaseModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.models import Azure
from prowler.lib.outputs.finding import Finding


class AzureCIS(ComplianceOutput):
    def transform(
        self, findings: list[Finding], compliance: ComplianceBaseModel
    ) -> None:
        for finding in findings:
            for requirement in compliance.Requirements:
                for attribute in requirement.Attributes:
                    compliance_row = Azure(
                        Provider=finding.provider,
                        Description=compliance.Description,
                        Subscription=finding.subscription,
                        AssessmentDate=str(finding.timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Description=requirement.Description,
                        Requirements_Attributes_Section=attribute.Section,
                        Requirements_Attributes_Profile=attribute.Profile,
                        Requirements_Attributes_AssessmentStatus=attribute.AssessmentStatus,
                        Requirements_Attributes_Description=attribute.Description,
                        Requirements_Attributes_RationaleStatement=attribute.RationaleStatement,
                        Requirements_Attributes_ImpactStatement=attribute.ImpactStatement,
                        Requirements_Attributes_RemediationProcedure=attribute.RemediationProcedure,
                        Requirements_Attributes_AuditProcedure=attribute.AuditProcedure,
                        Requirements_Attributes_AdditionalInformation=attribute.AdditionalInformation,
                        Requirements_Attributes_DefaultValue=attribute.DefaultValue,
                        Requirements_Attributes_References=attribute.References,
                        Status=finding.status,
                        StatusExtended=finding.status_extended,
                        ResourceId=finding.resource_id,
                        ResourceName=finding.resource_name,
                        CheckId=finding.check_id,
                        Muted=finding.muted,
                    )
                    self._data.append(compliance_row)

    def batch_write_data_to_file(self, header: bool) -> None:
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                csv_writer = DictWriter(
                    self._file_descriptor,
                    fieldnames=[
                        field.upper() for field in self._data[0].__dict__.keys()
                    ],
                    delimiter=";",
                )
                if header:
                    csv_writer.writeheader()
                for finding in self._data:
                    for key in list(finding.__dict__.keys()):
                        finding.__dict__[key.upper()] = finding.__dict__.pop(key)
                    csv_writer.writerow(finding.dict())
                self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
