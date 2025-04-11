from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class M365IdentityInfo(BaseModel):
    identity_id: str = ""
    identity_type: str = ""
    tenant_id: str = ""
    tenant_domain: str = "Unknown tenant domain (missing AAD permissions)"
    location: str = ""


class M365RegionConfig(BaseModel):
    name: str = ""
    authority: str = None
    base_url: str = ""
    credential_scopes: list = []


class M365Credentials(BaseModel):
    user: str = ""
    passwd: str = ""


class M365OutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call Provider_Output_Options init
        super().__init__(arguments, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            if (
                identity.tenant_domain
                != "Unknown tenant domain (missing AAD permissions)"
            ):
                self.output_filename = (
                    f"prowler-output-{identity.tenant_domain}-{output_file_timestamp}"
                )
            else:
                self.output_filename = (
                    f"prowler-output-{identity.tenant_id}-{output_file_timestamp}"
                )
        else:
            self.output_filename = arguments.output_filename
