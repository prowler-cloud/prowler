from dataclasses import dataclass
from typing import Any, Optional

from azure.identity import DefaultAzureCredential
from pydantic import BaseModel


class Azure_Identity_Info(BaseModel):
    identity_id: str = ""
    identity_type: str = ""
    tenant_ids: list[str] = []
    domain: str = ""
    subscriptions: dict = {}


@dataclass
class Azure_Audit_Info:
    credentials: DefaultAzureCredential
    identity: Azure_Identity_Info
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]

    def __init__(self, credentials, identity, audit_metadata, audit_resources):
        self.credentials = credentials
        self.identity = identity
        self.audit_metadata = audit_metadata
        self.audit_resources = audit_resources
