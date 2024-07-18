from pydantic import BaseModel


class AWSMitreAttackModel(BaseModel):
    """
    AWSMitreAttackModel generates a finding's output in CSV MITRE ATTACK format for AWS.
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
    ResourceName: str


class AzureMitreAttackModel(BaseModel):
    """
    AzureMitreAttackModel generates a finding's output in CSV MITRE ATTACK format for Azure.
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
    ResourceName: str
    Location: str


class GCPMitreAttackModel(BaseModel):
    """
    GCPMitreAttackModel generates a finding's output in CSV MITRE ATTACK format for AWS.
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
    ResourceName: str
    Location: str


# TODO: Create a parent class for the common fields of MITRE ATT&CK and have the specific classes from each provider to inherit from it.
# It is not done yet because it is needed to respect the current order of the fields in the output file.
