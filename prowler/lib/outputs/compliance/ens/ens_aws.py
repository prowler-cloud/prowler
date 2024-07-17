from csv import DictWriter

from prowler.lib import logger
from prowler.lib.check.compliance_models import ComplianceBaseModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.ens.models import AWSENSModel
from prowler.lib.outputs.finding import Finding


class AWSENS(ComplianceOutput):
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
                        compliance_row = AWSENSModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            AccountId=finding.account_uid,
                            Region=finding.region,
                            AssessmentDate=str(finding.timestamp),
                            Requirements_Id=requirement.Id,
                            Requirements_Description=requirement.Description,
                            Requirements_Attributes_IdGrupoControl=attribute.IdGrupoControl,
                            Requirements_Attributes_Marco=attribute.Marco,
                            Requirements_Attributes_Categoria=attribute.Categoria,
                            Requirements_Attributes_DescripcionControl=attribute.DescripcionControl,
                            Requirements_Attributes_Nivel=attribute.Nivel,
                            Requirements_Attributes_Tipo=attribute.Tipo,
                            Requirements_Attributes_Dimensiones=",".join(
                                attribute.Dimensiones
                            ),
                            Requirements_Attributes_ModoEjecucion=attribute.ModoEjecucion,
                            Requirements_Attributes_Dependencias=",".join(
                                attribute.Dependencias
                            ),
                            Status=finding.status,
                            StatusExtended=finding.status_extended,
                            ResourceId=finding.resource_uid,
                            ResourceName=finding.resource_name,
                            CheckId=finding.check_id,
                            Muted=finding.muted,
                        )
                        self._data.append(compliance_row)
        # Add manual requirements to the compliance output
        for requirement in compliance.Requirements:
            if not requirement.Checks:
                for attribute in requirement.Attributes:
                    compliance_row = AWSENSModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        AccountId="",
                        Region="",
                        AssessmentDate=str(finding.timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Description=requirement.Description,
                        Requirements_Attributes_IdGrupoControl=attribute.IdGrupoControl,
                        Requirements_Attributes_Marco=attribute.Marco,
                        Requirements_Attributes_Categoria=attribute.Categoria,
                        Requirements_Attributes_DescripcionControl=attribute.DescripcionControl,
                        Requirements_Attributes_Nivel=attribute.Nivel,
                        Requirements_Attributes_Tipo=attribute.Tipo,
                        Requirements_Attributes_Dimensiones=",".join(
                            attribute.Dimensiones
                        ),
                        Requirements_Attributes_ModoEjecucion=attribute.ModoEjecucion,
                        Requirements_Attributes_Dependencias=",".join(
                            attribute.Dependencias
                        ),
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
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
