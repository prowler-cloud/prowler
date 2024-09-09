from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.mitre_attack.models import GCPMitreAttackModel
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.utils import unroll_list


class GCPMitreAttack(ComplianceOutput):
    """
    This class represents the GCP MITRE ATT&CK compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into GCP MITRE ATT&CK compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into GCP MITRE ATT&CK compliance format.

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
                    compliance_row = GCPMitreAttackModel(
                        Provider=finding.provider,
                        Description=compliance.Description,
                        ProjectId=finding.account_uid,
                        Location=finding.region,
                        AssessmentDate=str(finding.timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Name=requirement.Name,
                        Requirements_Description=requirement.Description,
                        Requirements_Tactics=unroll_list(requirement.Tactics),
                        Requirements_SubTechniques=unroll_list(
                            requirement.SubTechniques
                        ),
                        Requirements_Platforms=unroll_list(requirement.Platforms),
                        Requirements_TechniqueURL=requirement.TechniqueURL,
                        Requirements_Attributes_Services=", ".join(
                            attribute.GCPService for attribute in requirement.Attributes
                        ),
                        Requirements_Attributes_Categories=", ".join(
                            attribute.Category for attribute in requirement.Attributes
                        ),
                        Requirements_Attributes_Values=", ".join(
                            attribute.Value for attribute in requirement.Attributes
                        ),
                        Requirements_Attributes_Comments=", ".join(
                            attribute.Comment for attribute in requirement.Attributes
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
                    compliance_row = GCPMitreAttackModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        ProjectId="",
                        Location="",
                        AssessmentDate=str(finding.timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Name=requirement.Name,
                        Requirements_Description=requirement.Description,
                        Requirements_Tactics=unroll_list(requirement.Tactics),
                        Requirements_SubTechniques=unroll_list(
                            requirement.SubTechniques
                        ),
                        Requirements_Platforms=unroll_list(requirement.Platforms),
                        Requirements_TechniqueURL=requirement.TechniqueURL,
                        Requirements_Attributes_Services=", ".join(
                            attribute.GCPService for attribute in requirement.Attributes
                        ),
                        Requirements_Attributes_Categories=", ".join(
                            attribute.Category for attribute in requirement.Attributes
                        ),
                        Requirements_Attributes_Values=", ".join(
                            attribute.Value for attribute in requirement.Attributes
                        ),
                        Requirements_Attributes_Comments=", ".join(
                            attribute.Comment for attribute in requirement.Attributes
                        ),
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                    )
                    self._data.append(compliance_row)
