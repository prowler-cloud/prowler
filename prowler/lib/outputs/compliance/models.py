from typing import Optional

from pydantic import BaseModel

# TODO: move this to outputs/<compliance>/models.py


class Check_Output_CSV_Generic_Compliance(BaseModel):
    """
    Check_Output_CSV_Generic_Compliance generates a finding's output in CSV Generic Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: Optional[str]
    Requirements_Attributes_SubSection: Optional[str]
    Requirements_Attributes_SubGroup: Optional[str]
    Requirements_Attributes_Service: Optional[str]
    Requirements_Attributes_Type: Optional[str]
    Status: str
    StatusExtended: str
    ResourceId: str
    CheckId: str
    Muted: bool


class Check_Output_CSV_AWS_ISO27001_2013(BaseModel):
    """
    Check_Output_CSV_AWS_ISO27001_2013 generates a finding's output in CSV AWS ISO27001 Compliance format.
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
