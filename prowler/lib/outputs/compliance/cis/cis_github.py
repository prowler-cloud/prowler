from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import GithubCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class GithubCIS(ComplianceOutputBase):
    """This class represents the GitHub CIS compliance output."""


    @property
    def model(self) -> Type[GithubCISModel]:
        """Returns the specific GithubCISModel."""
        return GithubCISModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "Account_Id": "",
                "Account_Name": "",
            }
        return {
            "Account_Id": finding.account_uid,
            "Account_Name": finding.account_name,
        }
