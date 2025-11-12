from typing import Optional

from pydantic.v1 import BaseModel


class AWSC5Model(BaseModel):
    """
    AWSC5Model generates a finding's output in AWS C5 Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: str = None
    Requirements_Attributes_Type: str = None
    Requirements_Attributes_AboutCriteria: Optional[str] = None
    Requirements_Attributes_ComplementaryCriteria: Optional[str] = None
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
    Framework: str
    Name: str


class AzureC5Model(BaseModel):
    """
    AzureC5Model generates a finding's output in Azure C5 Compliance format.
    """

    Provider: str
    Description: str
    SubscriptionId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: str = None
    Requirements_Attributes_Type: str = None
    Requirements_Attributes_AboutCriteria: Optional[str] = None
    Requirements_Attributes_ComplementaryCriteria: Optional[str] = None
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
    Framework: str
    Name: str


class GCPC5Model(BaseModel):
    """
    GCPC5Model generates a finding's output in GCP C5 Compliance format.
    """

    Provider: str
    Description: str
    ProjectId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: str = None
    Requirements_Attributes_Type: str = None
    Requirements_Attributes_AboutCriteria: Optional[str] = None
    Requirements_Attributes_ComplementaryCriteria: Optional[str] = None
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
    Framework: str
    Name: str
