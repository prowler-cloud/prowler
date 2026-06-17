from prowler.config.config import timestamp
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutput
from prowler.lib.outputs.compliance.generic.models import GenericComplianceModel
from prowler.lib.outputs.finding import Finding


class GenericCompliance(ComplianceOutput):
    """
    This class represents the Generic compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Generic compliance format.
    """

    def transform(
        self,
        findings: list[Finding],
        compliance: Compliance,
        compliance_name: str,
    ) -> None:
        """
        Transforms a list of findings into Generic compliance format.

        Parameters:
            - findings (list): A list of findings.
            - compliance (Compliance): A compliance model.
            - compliance_name (str): The name of the compliance model.

        Returns:
            - None
        """

        def compliance_row(requirement, attribute, finding=None):
            # Read attribute fields defensively: GenericCompliance is the
            # last-resort renderer for any framework, and provider-specific
            # schemas (e.g. CIS, ENS, ISO27001) do not declare the universal
            # Section/SubSection/SubGroup/Service/Type/Comment fields.
            return GenericComplianceModel(
                Provider=(finding.provider if finding else compliance.Provider.lower()),
                Description=compliance.Description,
                AccountId=finding.account_uid if finding else "",
                Region=finding.region if finding else "",
                AssessmentDate=str(timestamp),
                Requirements_Id=requirement.Id,
                Requirements_Description=requirement.Description,
                Requirements_Attributes_Section=getattr(attribute, "Section", None),
                Requirements_Attributes_SubSection=getattr(
                    attribute, "SubSection", None
                ),
                Requirements_Attributes_SubGroup=getattr(attribute, "SubGroup", None),
                Requirements_Attributes_Service=getattr(attribute, "Service", None),
                Requirements_Attributes_Type=getattr(attribute, "Type", None),
                Requirements_Attributes_Comment=getattr(attribute, "Comment", None),
                Status=finding.status if finding else "MANUAL",
                StatusExtended=(finding.status_extended if finding else "Manual check"),
                ResourceId=finding.resource_uid if finding else "manual_check",
                ResourceName=finding.resource_name if finding else "Manual check",
                CheckId=finding.check_id if finding else "manual",
                Muted=finding.muted if finding else False,
                Framework=compliance.Framework,
                Name=compliance.Name,
            )

        for finding in findings:
            for requirement in compliance.Requirements:
                # Source of truth: framework JSON, not finding.compliance snapshot (avoids CSV/UI count drift).
                if finding.check_id in requirement.Checks:
                    for attribute in requirement.Attributes:
                        self._data.append(
                            compliance_row(requirement, attribute, finding)
                        )
        # Add manual requirements to the compliance output
        for requirement in compliance.Requirements:
            if not requirement.Checks:
                for attribute in requirement.Attributes:
                    self._data.append(compliance_row(requirement, attribute))
