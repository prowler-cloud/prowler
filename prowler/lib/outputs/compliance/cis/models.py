from pydantic import BaseModel


class CIS(BaseModel):
    """
    CIS generates a finding's output in CIS Compliance format.
    """

    Provider: str
    Description: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_Profile: str
    Requirements_Attributes_AssessmentStatus: str
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
    CheckId: str
    Muted: bool


class AWS(CIS):
    """
    AWS CIS Compliance format.
    """

    AccountId: str
    Region: str


class Azure(CIS):
    """
    Azure CIS Compliance format.
    """

    Subscription: str
    Location: str


class GCP(CIS):
    """
    GCP CIS Compliance format.
    """

    ProjectId: str
    Location: str


class Kubernetes(CIS):
    """
    Kubernetes CIS Compliance format.
    """

    Context: str
    Namespace: str
