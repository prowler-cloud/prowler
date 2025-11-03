from typing import Optional

from pydantic import BaseModel


class CCC_AWSModel(BaseModel):
    """
    CCC_AWSModel generates a finding's output in AWS CCC Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_FamilyName: str
    Requirements_Attributes_FamilyDescription: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str]
    Requirements_Attributes_SubSectionObjective: str
    Requirements_Attributes_Applicability: list[str]
    Requirements_Attributes_Recommendation: str
    Requirements_Attributes_SectionThreatMappings: list[dict]
    Requirements_Attributes_SectionGuidelineMappings: list[dict]
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class CCC_AzureModel(BaseModel):
    """
    CCC_AzureModel generates a finding's output in Azure CCC Compliance format.
    """

    Provider: str
    Description: str
    SubscriptionId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_FamilyName: str
    Requirements_Attributes_FamilyDescription: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str]
    Requirements_Attributes_SubSectionObjective: str
    Requirements_Attributes_Applicability: list[str]
    Requirements_Attributes_Recommendation: str
    Requirements_Attributes_SectionThreatMappings: list[dict]
    Requirements_Attributes_SectionGuidelineMappings: list[dict]
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class CCC_GCPModel(BaseModel):
    """
    CCC_GCPModel generates a finding's output in GCP CCC Compliance format.
    """

    Provider: str
    Description: str
    ProjectId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_FamilyName: str
    Requirements_Attributes_FamilyDescription: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str]
    Requirements_Attributes_SubSectionObjective: str
    Requirements_Attributes_Applicability: list[str]
    Requirements_Attributes_Recommendation: str
    Requirements_Attributes_SectionThreatMappings: list[dict]
    Requirements_Attributes_SectionGuidelineMappings: list[dict]
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
