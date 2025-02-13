from typing import Optional

from pydantic import BaseModel


class ProwlerThreatScoreAWSModel(BaseModel):
    """
    ProwlerThreatScoreAWSModel generates a finding's output in AWS Prowler ThreatScore Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Title: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str]
    Requirements_Attributes_AttributeDescription: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_LevelOfRisk: int
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
