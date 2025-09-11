from typing import Optional

from pydantic.v1 import BaseModel


class AWSCISModel(BaseModel):
    """
    AWSCISModel generates a finding's output in AWS CIS Compliance format.
    """

    Provider: str
    Description: str
    AccountId: str
    Region: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_Profile: str
    Requirements_Attributes_AssessmentStatus: str
    Requirements_Attributes_Description: str
    Requirements_Attributes_RationaleStatement: str
    Requirements_Attributes_ImpactStatement: str
    Requirements_Attributes_RemediationProcedure: str
    Requirements_Attributes_AuditProcedure: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_DefaultValue: Optional[str] = (
        None  # TODO Optional for now since it's not present in the CIS 1.5, 2.0 and 3.0 AWS benchmark
    )
    Requirements_Attributes_References: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class AzureCISModel(BaseModel):
    """
    AzureCISModel generates a finding's output in Azure CIS Compliance format.
    """

    Provider: str
    Description: str
    SubscriptionId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_Profile: str
    Requirements_Attributes_AssessmentStatus: str
    Requirements_Attributes_Description: str
    Requirements_Attributes_RationaleStatement: str
    Requirements_Attributes_ImpactStatement: str
    Requirements_Attributes_RemediationProcedure: str
    Requirements_Attributes_AuditProcedure: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_DefaultValue: str
    Requirements_Attributes_References: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class M365CISModel(BaseModel):
    """
    M365CISModel generates a finding's output in Microsoft 365 CIS Compliance format.
    """

    Provider: str
    Description: str
    TenantId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_Profile: str
    Requirements_Attributes_AssessmentStatus: str
    Requirements_Attributes_Description: str
    Requirements_Attributes_RationaleStatement: str
    Requirements_Attributes_ImpactStatement: str
    Requirements_Attributes_RemediationProcedure: str
    Requirements_Attributes_AuditProcedure: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_DefaultValue: str
    Requirements_Attributes_References: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class GCPCISModel(BaseModel):
    """
    GCPCISModel generates a finding's output in GCP CIS Compliance format.
    """

    Provider: str
    Description: str
    ProjectId: str
    Location: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
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
    ResourceName: str
    CheckId: str
    Muted: bool


class KubernetesCISModel(BaseModel):
    """
    KubernetesCISModel generates a finding's output in Kubernetes CIS Compliance format.
    """

    Provider: str
    Description: str
    Context: str
    Namespace: str
    AssessmentDate: str
    Requirements_Id: str
    Requirements_Description: str
    Requirements_Attributes_Section: str
    Requirements_Attributes_SubSection: Optional[str] = None
    Requirements_Attributes_Profile: Optional[str] = None
    Requirements_Attributes_AssessmentStatus: str
    Requirements_Attributes_Description: str
    Requirements_Attributes_RationaleStatement: str
    Requirements_Attributes_ImpactStatement: str
    Requirements_Attributes_RemediationProcedure: str
    Requirements_Attributes_AuditProcedure: str
    Requirements_Attributes_AdditionalInformation: str
    Requirements_Attributes_References: str
    Requirements_Attributes_DefaultValue: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


class GithubCISModel(BaseModel):
    """
    GithubCISModel generates a finding's output in Github CIS Compliance format.
    """

    Provider: str
    Description: str
    Account_Name: str
    Account_Id: str
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
    Requirements_Attributes_DefaultValue: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool


# TODO: Create a parent class for the common fields of CIS and have the specific classes from each provider to inherit from it.
# It is not done yet because it is needed to respect the current order of the fields in the output file.

# class AWS(CIS):
#     """
#     AWS CIS Compliance format.
#     """

#     AccountId: str
#     Region: str


# class Azure(CIS):
#     """
#     Azure CIS Compliance format.
#     """

#     Subscription: str
#     Location: str


# class GCP(CIS):
#     """
#     GCP CIS Compliance format.
#     """

#     ProjectId: str
#     Location: str


# class Kubernetes(CIS):
#     """
#     Kubernetes CIS Compliance format.
#     """

#     Context: str
#     Namespace: str
