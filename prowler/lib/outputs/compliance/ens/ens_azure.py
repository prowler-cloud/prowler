from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.ens.models import AzureENSModel
from prowler.lib.outputs.finding import Finding


class AzureENS(ComplianceOutput):
    """
    This class represents the Azure ENS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure ENS compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into AWS ENS compliance format.

        Parameters:
            - findings (list): A list of findings.
            - compliance (Compliance): A compliance model.
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
                        compliance_row = AzureENSModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            SubscriptionId=finding.account_name,
                            Location=finding.region,
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
                    compliance_row = AzureENSModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        SubscriptionId="",
                        Location="",
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
