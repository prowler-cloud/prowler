from typing import Optional

from pydantic.v1 import BaseModel


class GoogleWorkspaceCISASCuBAModel(BaseModel):
    """
    GoogleWorkspaceCISASCuBAModel generates a finding's output in Google Workspace CISA SCuBA Compliance format.
    """

    Provider: str
    Description: str
    Domain: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: Optional[str] = None
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_Service: Optional[str] = None
    Requirements_Attributes_Type: Optional[str] = None
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
    Framework: str
    Name: str
