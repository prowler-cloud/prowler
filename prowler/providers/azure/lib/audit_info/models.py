from dataclasses import dataclass

from azure.identity import DefaultAzureCredential
from pydantic import BaseModel


class Azure_Identity_Info(BaseModel):
    identity_id: str = None
    identity_type: str = None
    tenant_ids: list[str] = []
    domain: str = None
    subscriptions: dict = {}


@dataclass
class Azure_Audit_Info:
    credentials: DefaultAzureCredential
    identity: Azure_Identity_Info

    def __init__(self, credentials, identity):
        self.credentials = credentials
        self.identity = identity
