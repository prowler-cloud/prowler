from pydantic import BaseModel


class MitreAttackAWS(BaseModel):
    """
    MitreAttackAWS generates a finding's output in CSV MITRE ATTACK format for AWS.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Name: str
    Requirements_Description: str
    Requirements_Tactics: str
    Requirements_SubTechniques: str
    Requirements_Platforms: str
    Requirements_TechniqueURL: str
    Requirements_Attributes_Services: str
    Requirements_Attributes_Categories: str
    Requirements_Attributes_Values: str
    Requirements_Attributes_Comments: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool


class MitreAttackAzure(BaseModel):
    """
    MitreAttackAzure generates a finding's output in CSV MITRE ATTACK format for Azure.
    """

    Provider: str
    Description: str
    SubscriptionId: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Name: str
    Requirements_Description: str
    Requirements_Tactics: str
    Requirements_SubTechniques: str
    Requirements_Platforms: str
    Requirements_TechniqueURL: str
    Requirements_Attributes_Services: str
    Requirements_Attributes_Categories: str
    Requirements_Attributes_Values: str
    Requirements_Attributes_Comments: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool


class MitreAttackGCP(BaseModel):
    """
    MitreAttackGCP generates a finding's output in CSV MITRE ATTACK format for AWS.
    """

    Provider: str
    Description: str
    ProjectId: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Name: str
    Requirements_Description: str
    Requirements_Tactics: str
    Requirements_SubTechniques: str
    Requirements_Platforms: str
    Requirements_TechniqueURL: str
    Requirements_Attributes_Services: str
    Requirements_Attributes_Categories: str
    Requirements_Attributes_Values: str
    Requirements_Attributes_Comments: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool
