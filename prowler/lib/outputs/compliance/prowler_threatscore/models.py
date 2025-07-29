from typing import Optional

from pydantic.v1 import BaseModel


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
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_AttributeDescription: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_LevelOfRisk: int
    Requirements_Attributes_Weight: int
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class ProwlerThreatScoreAzureModel(BaseModel):
    """
    ProwlerThreatScoreAzureModel generates a finding's output in Azure Prowler ThreatScore Compliance format.
    """

    Provider: str
    Description: str
    SubscriptionId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Title: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_AttributeDescription: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_LevelOfRisk: int
    Requirements_Attributes_Weight: int
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class ProwlerThreatScoreGCPModel(BaseModel):
    """
    ProwlerThreatScoreGCPModel generates a finding's output in GCP Prowler ThreatScore Compliance format.
    """

    Provider: str
    Description: str
    ProjectId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Title: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_AttributeDescription: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_LevelOfRisk: int
    Requirements_Attributes_Weight: int
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class ProwlerThreatScoreM365Model(BaseModel):
    """
    ProwlerThreatScoreM365Model generates a finding's output in M365 Prowler ThreatScore Compliance format.
    """

    Provider: str
    Description: str
    TenantId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Title: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_AttributeDescription: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_LevelOfRisk: int
    Requirements_Attributes_Weight: int
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
