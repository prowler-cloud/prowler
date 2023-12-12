from dataclasses import dataclass
from typing import Any, Optional

from azure.identity import DefaultAzureCredential
from pydantic import BaseModel


class AzureIdentityInfo(BaseModel):
    identity_id: str = ""
    identity_type: str = ""
    tenant_ids: list[str] = []
    domain: str = "Unknown tenant domain (missing AAD permissions)"
    subscriptions: dict = {}


class AzureRegionConfig(BaseModel):
    name: str = ""
    authority: str = None
    base_url: str = ""
    credential_scopes: list = []


@dataclass
class Azure_Audit_Info:
    credentials: DefaultAzureCredential
    identity: AzureIdentityInfo
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: dict
    azure_region_config: AzureRegionConfig

    def __init__(
        self,
        credentials,
        identity,
        audit_metadata,
        audit_resources,
        audit_config,
        AzureRegionConfig,
    ):
        self.credentials = credentials
        self.identity = identity
        self.audit_metadata = audit_metadata
        self.audit_resources = audit_resources
        self.audit_config = audit_config
        self.AzureRegionConfig = AzureRegionConfig
