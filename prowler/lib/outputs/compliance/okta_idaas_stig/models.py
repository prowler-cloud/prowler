from typing import Optional

from pydantic.v1 import BaseModel


class OktaIDaaSSTIGModel(BaseModel):
    """
    OktaIDaaSSTIGModel generates a finding's output in DISA Okta IDaaS STIG Compliance format.
    """

    Provider: str
    Description: str
    OrganizationDomain: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Name: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_Severity: str
    Requirements_Attributes_RuleID: str
    Requirements_Attributes_StigID: str
    Requirements_Attributes_CCI: Optional[list[str]] = None
    Requirements_Attributes_CheckText: Optional[str] = None
    Requirements_Attributes_FixText: Optional[str] = None
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
    Framework: str
    Name: str
