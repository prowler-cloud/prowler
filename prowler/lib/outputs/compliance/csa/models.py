from pydantic.v1 import BaseModel


class AWSCSAModel(BaseModel):
    """
    AWSCSAModel generates a finding's output in CSV CSA format for AWS.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Name: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_CCMLite: str
    Requirements_Attributes_IaaS: str
    Requirements_Attributes_PaaS: str
    Requirements_Attributes_SaaS: str
    Requirements_Attributes_ScopeApplicability: list[dict]
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool
    ResourceName: str
    Framework: str
    Name: str
