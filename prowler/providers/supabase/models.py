from typing import Any

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class SupabaseSession(BaseModel):
    """Supabase Management API session."""

    access_token: str = Field(exclude=True, repr=False)
    base_url: str = "https://api.supabase.com"
    http_session: Any = Field(default=None, exclude=True, repr=False)


class SupabaseOrganization(BaseModel):
    """Supabase organization visible to the authenticated account."""

    id: str
    slug: str
    name: str


class SupabaseIdentityInfo(BaseModel):
    """Supabase identity and organization scope."""

    organizations: list[SupabaseOrganization] = Field(default_factory=list)


class SupabaseOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Supabase scans."""

    def __init__(self, arguments, bulk_checks_metadata, identity: SupabaseIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)
        if getattr(arguments, "output_filename", None) is None:
            fragment = (
                identity.organizations[0].slug if identity.organizations else "supabase"
            )
            self.output_filename = f"prowler-output-{fragment}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename
