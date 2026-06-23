from prowler.config.config import timestamp
from prowler.lib.check.compliance_config_eval import (
    apply_config_status,
    build_requirement_config_status,
)
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.ccc.models import CCC_GCPModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.finding import Finding


class CCC_GCP(ComplianceOutput):
    """
    This class represents the GCP CCC compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into GCP CCC compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into GCP CCC compliance format.

        Parameters:
            - findings (list): A list of findings.
            - compliance (Compliance): A compliance model.
            - compliance_name (str): The name of the compliance model.

        Returns:
            - None
        """
        # Evaluate each requirement's config constraints once against the
        # scan-global applied config; a requirement whose configurable checks
        # ran with a config too loose to trust is forced to FAIL.
        requirement_config_status = build_requirement_config_status(
            compliance.Requirements
        )

        for finding in findings:
            for requirement in compliance.Requirements:
                # Source of truth: framework JSON, not finding.compliance snapshot (avoids CSV/UI count drift).
                if finding.check_id in requirement.Checks:
                    row_status, row_status_extended = apply_config_status(
                        finding.status,
                        finding.status_extended,
                        requirement_config_status.get(requirement.Id),
                    )
                    for attribute in requirement.Attributes:
                        compliance_row = CCC_GCPModel(
                            Provider=finding.provider,
                            Description=compliance.Description,
                            ProjectId=finding.account_uid,
                            Location=finding.region,
                            AssessmentDate=str(timestamp),
                            Requirements_Id=requirement.Id,
                            Requirements_Description=requirement.Description,
                            Requirements_Attributes_FamilyName=attribute.FamilyName,
                            Requirements_Attributes_FamilyDescription=attribute.FamilyDescription,
                            Requirements_Attributes_Section=attribute.Section,
                            Requirements_Attributes_SubSection=attribute.SubSection,
                            Requirements_Attributes_SubSectionObjective=attribute.SubSectionObjective,
                            Requirements_Attributes_Applicability=attribute.Applicability,
                            Requirements_Attributes_Recommendation=attribute.Recommendation,
                            Requirements_Attributes_SectionThreatMappings=attribute.SectionThreatMappings,
                            Requirements_Attributes_SectionGuidelineMappings=attribute.SectionGuidelineMappings,
                            Status=row_status,
                            StatusExtended=row_status_extended,
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
                    compliance_row = CCC_GCPModel(
                        Provider=compliance.Provider.lower(),
                        Description=compliance.Description,
                        ProjectId="",
                        Location="",
                        AssessmentDate=str(timestamp),
                        Requirements_Id=requirement.Id,
                        Requirements_Description=requirement.Description,
                        Requirements_Attributes_FamilyName=attribute.FamilyName,
                        Requirements_Attributes_FamilyDescription=attribute.FamilyDescription,
                        Requirements_Attributes_Section=attribute.Section,
                        Requirements_Attributes_SubSection=attribute.SubSection,
                        Requirements_Attributes_SubSectionObjective=attribute.SubSectionObjective,
                        Requirements_Attributes_Applicability=attribute.Applicability,
                        Requirements_Attributes_Recommendation=attribute.Recommendation,
                        Requirements_Attributes_SectionThreatMappings=attribute.SectionThreatMappings,
                        Requirements_Attributes_SectionGuidelineMappings=attribute.SectionGuidelineMappings,
                        Status="MANUAL",
                        StatusExtended="Manual check",
                        ResourceId="manual_check",
                        ResourceName="Manual check",
                        CheckId="manual",
                        Muted=False,
                    )
                    self._data.append(compliance_row)
