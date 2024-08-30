from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.aws_well_architected.models import (
    AWSWellArchitectedModel,
)
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.finding import Finding


class AWSWellArchitected(ComplianceOutput):
    """
    This class represents the AWS Well-Architected compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS Well-Architected compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into AWS Well-Architected compliance format.

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
                        compliance_row = AWSWellArchitectedModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            AccountId=finding.account_uid,
                            Region=finding.region,
                            AssessmentDate=str(finding.timestamp),
                            Requirements_Id=requirement.Id,
                            Requirements_Description=requirement.Description,
                            Requirements_Attributes_Name=attribute.Name,
                            Requirements_Attributes_WellArchitectedQuestionId=attribute.WellArchitectedQuestionId,
                            Requirements_Attributes_WellArchitectedPracticeId=attribute.WellArchitectedPracticeId,
                            Requirements_Attributes_Section=attribute.Section,
                            Requirements_Attributes_SubSection=attribute.SubSection,
                            Requirements_Attributes_LevelOfRisk=attribute.LevelOfRisk,
                            Requirements_Attributes_AssessmentMethod=attribute.AssessmentMethod,
                            Requirements_Attributes_Description=attribute.Description,
                            Requirements_Attributes_ImplementationGuidanceUrl=attribute.ImplementationGuidanceUrl,
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
                    compliance_row = AWSWellArchitectedModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        AccountId="",
                        Region="",
                        AssessmentDate=str(finding.timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Description=requirement.Description,
                        Requirements_Attributes_Name=attribute.Name,
                        Requirements_Attributes_WellArchitectedQuestionId=attribute.WellArchitectedQuestionId,
                        Requirements_Attributes_WellArchitectedPracticeId=attribute.WellArchitectedPracticeId,
                        Requirements_Attributes_Section=attribute.Section,
                        Requirements_Attributes_SubSection=attribute.SubSection,
                        Requirements_Attributes_LevelOfRisk=attribute.LevelOfRisk,
                        Requirements_Attributes_AssessmentMethod=attribute.AssessmentMethod,
                        Requirements_Attributes_Description=attribute.Description,
                        Requirements_Attributes_ImplementationGuidanceUrl=attribute.ImplementationGuidanceUrl,
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                    )
                    self._data.append(compliance_row)
