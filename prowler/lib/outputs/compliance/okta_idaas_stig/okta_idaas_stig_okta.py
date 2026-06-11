from prowler.config.config import timestamp
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.okta_idaas_stig.models import OktaIDaaSSTIGModel
from prowler.lib.outputs.finding import Finding


class OktaIDaaSSTIG(ComplianceOutput):
    """
    This class represents the Okta IDaaS STIG compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Okta IDaaS STIG compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        _compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into Okta IDaaS STIG compliance format.

        Parameters:
            - findings (list): A list of findings.
            - compliance (Compliance): A compliance model.
            - _compliance_name (str): The name of the compliance model (unused).

        Returns:
            - None
        """
        for finding in findings:
            for requirement in compliance.Requirements:
                # Source of truth: framework JSON, not finding.compliance snapshot (avoids CSV/UI count drift).
                if finding.check_id in requirement.Checks:
                    for attribute in requirement.Attributes:
                        compliance_row = OktaIDaaSSTIGModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            OrganizationDomain=finding.account_name,
                            AssessmentDate=str(timestamp),
                            Requirements_Id=requirement.Id,
                            Requirements_Name=requirement.Name,
                            Requirements_Description=requirement.Description,
                            Requirements_Attributes_Section=attribute.Section,
                            Requirements_Attributes_Severity=attribute.Severity.value,
                            Requirements_Attributes_RuleID=attribute.RuleID,
                            Requirements_Attributes_StigID=attribute.StigID,
                            Requirements_Attributes_CCI=attribute.CCI,
                            Requirements_Attributes_CheckText=attribute.CheckText,
                            Requirements_Attributes_FixText=attribute.FixText,
                            Status=finding.status,
                            StatusExtended=finding.status_extended,
                            ResourceId=finding.resource_uid,
                            ResourceName=finding.resource_name,
                            CheckId=finding.check_id,
                            Muted=finding.muted,
                            Framework=compliance.Framework,
                            Name=compliance.Name,
                        )
                        self._data.append(compliance_row)
        # Add manual requirements to the compliance output
        for requirement in compliance.Requirements:
            if not requirement.Checks:
                for attribute in requirement.Attributes:
                    compliance_row = OktaIDaaSSTIGModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        OrganizationDomain="",
                        AssessmentDate=str(timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Name=requirement.Name,
                        Requirements_Description=requirement.Description,
                        Requirements_Attributes_Section=attribute.Section,
                        Requirements_Attributes_Severity=attribute.Severity.value,
                        Requirements_Attributes_RuleID=attribute.RuleID,
                        Requirements_Attributes_StigID=attribute.StigID,
                        Requirements_Attributes_CCI=attribute.CCI,
                        Requirements_Attributes_CheckText=attribute.CheckText,
                        Requirements_Attributes_FixText=attribute.FixText,
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                        Framework=compliance.Framework,
                        Name=compliance.Name,
                    )
                    self._data.append(compliance_row)
