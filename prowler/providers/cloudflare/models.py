from typing import Any, Optional

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class CloudflareSession(BaseModel):
    """Cloudflare session information."""

    client: Any
    api_token: Optional[str] = None
    api_key: Optional[str] = None
    api_email: Optional[str] = None


class CloudflareAccount(BaseModel):
    """Cloudflare account metadata."""

    id: str
    name: str
    type: Optional[str] = None


class CloudflareIdentityInfo(BaseModel):
    """Cloudflare identity and scoping information."""

    user_id: Optional[str] = None
    email: Optional[str] = None
    accounts: list[CloudflareAccount] = Field(default_factory=list)
    audited_accounts: list[str] = Field(default_factory=list)
    audited_zone: list[str] = Field(default_factory=list)


class CloudflareOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Cloudflare scans."""

    def __init__(
        self, arguments, bulk_checks_metadata, identity: CloudflareIdentityInfo
    ):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = (
                identity.audited_accounts[0]
                if identity.audited_accounts
                else identity.email or "cloudflare"
            )
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
