from typing import Optional

from pydantic.v1 import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class CloudflareSession(BaseModel):
    """Cloudflare session model storing authentication credentials"""

    api_token: Optional[str] = None
    api_key: Optional[str] = None
    api_email: Optional[str] = None


class CloudflareIdentityInfo(BaseModel):
    """Cloudflare account identity information"""

    account_id: str
    account_name: str
    account_email: str


class CloudflareOutputOptions(ProviderOutputOptions):
    """Cloudflare-specific output options"""

    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call ProviderOutputOptions init
        super().__init__(arguments, bulk_checks_metadata)
        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.account_name}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
