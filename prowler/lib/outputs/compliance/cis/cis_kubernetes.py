from csv import DictWriter
from venv import logger

from prowler.lib.check.compliance_models import ComplianceBaseModel
from prowler.lib.outputs.compliance.cis.models import Kubernetes
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.finding import Finding


class KubernetesCIS(ComplianceOutput):
    """
    This class represents the Kubernetes CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Kubernetes CIS compliance format.
        - batch_write_data_to_file: Writes the findings data to a CSV file in Kubernetes CIS compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: ComplianceBaseModel,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into Kubernetes CIS compliance format.

        Parameters:
            - findings (list): A list of findings.
            - compliance (ComplianceBaseModel): A compliance model.
            - compliance_name (str): The name of the compliance model.

        Returns:
            - None
        """
        for finding in findings:
            # Get the compliance requirements for the finding
            finding_requirements = finding.compliance.get(compliance_name, [])
            for requirement in compliance.Requirements:
                if requirement.Id in finding_requirements:
                    for attribute in requirement.Attributes:
                        compliance_row = Kubernetes(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            Context=finding.account_name,
                            Namespace=finding.region,
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
                            Requirements_Attributes_References=attribute.References,
                            Requirements_Attributes_DefaultValue=attribute.DefaultValue,
                            Status=finding.status,
                            StatusExtended=finding.status_extended,
                            ResourceId=finding.resource_uid,
                            CheckId=finding.check_id,
                            Muted=finding.muted,
                        )
                        self._data.append(compliance_row)

    def batch_write_data_to_file(self) -> None:
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
                csv_writer.writeheader()
                for finding in self._data:
                    csv_writer.writerow(
                        {k.upper(): v for k, v in finding.dict().items()}
                    )
                self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
