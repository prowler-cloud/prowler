from typing import Any, Optional

from pydantic.v1 import BaseModel


class CISBaseModel(BaseModel):
    """
    CISBaseModel generates a finding's output in CIS Compliance format.
    """

    Provider: str
    Description: str
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
    Requirements_Attributes_DefaultValue: Optional[str] = None
    Requirements_Attributes_References: str
    Status: str
    StatusExtended: str
    ResourceId: str
    ResourceName: str
    CheckId: str
    Muted: bool
    Framework: str
    Name: str

    _excluded_fields: tuple = ()
    _swap_references_default_value: bool = False

    def dict(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Generate a dictionary representation of the model, ensuring specific column order.

        Args:
            *args: Variable length argument list passed to BaseModel.dict().
            **kwargs: Arbitrary keyword arguments passed to BaseModel.dict().

        Returns:
            dict: The dictionary representation of the model with enforced ordering for CIS outputs.
        """
        d = super().dict(*args, **kwargs)
        for field_name in self._excluded_fields:
            d.pop(field_name, None)

        base_fields = [
            f
            for f in CISBaseModel.__fields__.keys()
            if f not in ("Provider", "Description")
        ]
        if self._swap_references_default_value:
            if (
                "Requirements_Attributes_References" in base_fields
                and "Requirements_Attributes_DefaultValue" in base_fields
            ):
                idx_ref = base_fields.index("Requirements_Attributes_References")
                idx_def = base_fields.index("Requirements_Attributes_DefaultValue")
                if idx_def < idx_ref:
                    base_fields[idx_def], base_fields[idx_ref] = (
                        base_fields[idx_ref],
                        base_fields[idx_def],
                    )

        ordered_keys = []
        if "Provider" in d:
            ordered_keys.append("Provider")
        if "Description" in d:
            ordered_keys.append("Description")

        for key in d.keys():
            if key not in ordered_keys and key not in base_fields:
                ordered_keys.append(key)
        for key in base_fields:
            if key in d:
                ordered_keys.append(key)
        return {k: d[k] for k in ordered_keys}


class AWSCISModel(CISBaseModel):
    """
    AWSCISModel generates a finding's output in AWS CIS Compliance format.
    """

    AccountId: str
    Region: str


class AzureCISModel(CISBaseModel):
    """
    AzureCISModel generates a finding's output in Azure CIS Compliance format.
    """

    SubscriptionId: str
    Location: str


class M365CISModel(CISBaseModel):
    """
    M365CISModel generates a finding's output in Microsoft 365 CIS Compliance format.
    """

    TenantId: str
    Location: str


class GCPCISModel(CISBaseModel):
    """
    GCPCISModel generates a finding's output in GCP CIS Compliance format.
    """

    _excluded_fields = ("Requirements_Attributes_DefaultValue",)

    ProjectId: str
    Location: str


class KubernetesCISModel(CISBaseModel):
    """
    KubernetesCISModel generates a finding's output in Kubernetes CIS Compliance format.
    """

    _swap_references_default_value = True

    Context: str
    Cluster: str
    Namespace: str


class GithubCISModel(CISBaseModel):
    """
    GithubCISModel generates a finding's output in Github CIS Compliance format.
    """

    _excluded_fields = ("Requirements_Attributes_SubSection",)
    _swap_references_default_value = True

    Account_Name: str
    Account_Id: str


class OracleCloudCISModel(CISBaseModel):
    """
    OracleCloudCISModel generates a finding's output in Oracle Cloud CIS Compliance format.
    """

    TenancyId: str
    Region: str


class GoogleWorkspaceCISModel(CISBaseModel):
    """
    GoogleWorkspaceCISModel generates a finding's output in Google Workspace CIS Compliance format.
    """

    Domain: str


class AlibabaCloudCISModel(CISBaseModel):
    """
    AlibabaCloudCISModel generates a finding's output in Alibaba Cloud CIS Compliance format.
    """

    AccountId: str
    Region: str


# Compliance models alias for backwards compatibility
CIS_AWS = AWSCISModel
CIS_Azure = AzureCISModel
CIS_GCP = GCPCISModel
CIS_Kubernetes = KubernetesCISModel
CIS_M365 = M365CISModel
CIS_Github = GithubCISModel
CIS_OracleCloud = OracleCloudCISModel
CIS_AlibabaCloud = AlibabaCloudCISModel
CIS_GoogleWorkspace = GoogleWorkspaceCISModel
