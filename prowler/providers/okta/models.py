from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class OktaSession(BaseModel):
    org_url: str
    client_id: str
    scopes: list[str]
    private_key: str


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
