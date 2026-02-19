from typing import Optional

from pydantic.v1 import BaseModel


class GenericComplianceModel(BaseModel):
    """
    GenericComplianceModel generates a finding's output in Generic Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: Optional[str] = None
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_SubGroup: Optional[str] = None
    Requirements_Attributes_Service: Optional[str] = None
    Requirements_Attributes_Type: Optional[str] = None
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool
    ResourceName: str
    Framework: str
    Name: str
    Requirements_Attributes_Comment: Optional[str] = None
