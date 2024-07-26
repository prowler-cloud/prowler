from pydantic import BaseModel


class AWSISO27001Model(BaseModel):
    """
    AWSISO27001Model generates a finding's output in CSV AWS ISO27001 format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Attributes_Category: str
    Requirements_Attributes_Objetive_ID: str
    Requirements_Attributes_Objetive_Name: str
    Requirements_Attributes_Check_Summary: str
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool
    ResourceName: str
