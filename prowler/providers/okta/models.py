from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class OktaSession(BaseModel):
    org_url: str
    client_id: str
    scopes: list[str]
    private_key: str

    def to_sdk_config(self) -> dict:
        # Shared by the credential probe (OktaProvider.setup_identity) and
        # the service-level client (OktaService.__set_client__). Keeping the
        # builder in one place stops the two SDK config dicts from drifting.
        # DPoP proofs are sent on every token request — required by tenants
        # with "Demonstrating Proof of Possession" enabled on the service
        # app (or org-wide), harmless on tenants that don't.
        return {
            "orgUrl": self.org_url,
            "authorizationMode": "PrivateKey",
            "clientId": self.client_id,
            "scopes": self.scopes,
            "privateKey": self.private_key,
            "dpopEnabled": True,
        }


class OktaIdentityInfo(BaseModel):
    org_url: str
    client_id: str


class OktaOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            org_slug = (
                identity.org_url.replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
            )
            self.output_filename = f"prowler-output-{org_slug}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename
