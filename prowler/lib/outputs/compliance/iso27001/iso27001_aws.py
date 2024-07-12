from csv import DictWriter

from prowler.lib import logger
from prowler.lib.check.compliance_models import ComplianceBaseModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.iso27001.models import ISO27001AWS
from prowler.lib.outputs.finding import Finding


class AWSISO27001(ComplianceOutput):
    """
    This class represents the AWS ENS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS ENS compliance format.
        - batch_write_data_to_file: Writes the findings data to a CSV file in AWS ENS compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: ComplianceBaseModel,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into AWS ENS compliance format.

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
                        compliance_row = ISO27001AWS(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            AccountId=finding.account_uid,
                            Region=finding.region,
                            AssessmentDate=str(finding.timestamp),
                            Requirements_Attributes_Category=attribute.Category,
                            Requirements_Attributes_Objetive_ID=attribute.Objetive_ID,
                            Requirements_Attributes_Objetive_Name=attribute.Objetive_Name,
                            Requirements_Attributes_Check_Summary=attribute.Check_Summary,
                            Status=finding.status,
                            StatusExtended=finding.status_extended,
                            ResourceId=finding.resource_uid,
                            CheckId=finding.check_id,
                            Muted=finding.muted,
                            ResourceName=finding.resource_name,
                        )
                        self._data.append(compliance_row)

    def batch_write_data_to_file(self) -> None:
        """
        Writes the findings data to a CSV file in AWS ENS compliance format.

        Returns:
            - None
        """
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
