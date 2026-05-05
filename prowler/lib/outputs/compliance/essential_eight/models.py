from pydantic.v1 import BaseModel


class EssentialEightAWSModel(BaseModel):
    """
    EssentialEightAWSModel generates a finding's output in AWS ASD Essential Eight Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_MaturityLevel: str
    Requirements_Attributes_AssessmentStatus: str
    Requirements_Attributes_CloudApplicability: str
    Requirements_Attributes_MitigatedThreats: str
    Requirements_Attributes_Description: str
    Requirements_Attributes_RationaleStatement: str
    Requirements_Attributes_ImpactStatement: str
    Requirements_Attributes_RemediationProcedure: str
    Requirements_Attributes_AuditProcedure: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_References: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
    Framework: str
    Name: str
