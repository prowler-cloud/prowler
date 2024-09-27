from typing import Optional

from pydantic import BaseModel


class AWSKISAISMSPModel(BaseModel):
    """
    The AWS KISA-ISMS-P Model outputs findings in a format compliant with the AWS KISA-ISMS-P standard
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Name: str
    Requirements_Description: str
    Requirements_Attributes_Domain: str
    Requirements_Attributes_Subdomain: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_AuditChecklist: Optional[list[str]]
    Requirements_Attributes_RelatedRegulations: Optional[list[str]]
    Requirements_Attributes_AuditEvidence: Optional[list[str]]
    Requirements_Attributes_NonComplianceCases: Optional[list[str]]
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
