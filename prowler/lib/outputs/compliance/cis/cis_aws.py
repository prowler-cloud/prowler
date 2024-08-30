from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import AWSCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.finding import Finding


class AWSCIS(ComplianceOutput):
    """
    This class represents the AWS CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS CIS compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into AWS CIS compliance format.

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
                        compliance_row = AWSCISModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            AccountId=finding.account_uid,
                            Region=finding.region,
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
                    compliance_row = AWSCISModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        AccountId="",
                        Region="",
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
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                    )
                    self._data.append(compliance_row)
