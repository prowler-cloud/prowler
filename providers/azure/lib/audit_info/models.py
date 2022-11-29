from dataclasses import dataclass

from azure.identity import DefaultAzureCredential
from pydantic import BaseModel


class Azure_Identity_Info(BaseModel):
    id: str = None
    app_id: str = None
    tenant_id: str = None


@dataclass
class Azure_Audit_Info:
    credentials: DefaultAzureCredential
    identity: Azure_Identity_Info
    subscriptions: dict
    audited_account: str

    def __init__(self, credentials, identity, subscriptions):
        self.credentials = credentials
        self.identity = identity
        self.subscriptions = subscriptions
        self.audited_account = None
