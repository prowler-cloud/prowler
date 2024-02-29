from pydantic import BaseModel


class AzureIdentityInfo(BaseModel):
    identity_id: str = ""
    identity_type: str = ""
    tenant_ids: list[str] = []
    domain: str = "Unknown tenant domain (missing AAD permissions)"
    subscriptions: dict = {}
    locations: dict = {}


class AzureRegionConfig(BaseModel):
    name: str = ""
    authority: str = None
    base_url: str = ""
    credential_scopes: list = []
