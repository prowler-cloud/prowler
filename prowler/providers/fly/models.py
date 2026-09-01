from typing import Any, Optional

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class FlySession(BaseModel):
    """Fly.io API session information."""

    token: str = Field(exclude=True, repr=False)
    org_slug: Optional[str] = None
    machines_base_url: str = "https://api.machines.dev/v1"
    graphql_url: str = "https://api.fly.io/graphql"
    http_session: Any = Field(default=None, exclude=True)


class FlyOrganization(BaseModel):
    """Fly.io organization metadata."""

    id: str
    slug: str
    name: str = ""


class FlyIdentityInfo(BaseModel):
    """Fly.io identity and scoping information."""

    organization: Optional[FlyOrganization] = None
    organizations: list[FlyOrganization] = Field(default_factory=list)

    @property
    def org_slugs(self) -> list[str]:
        """Slugs of every organization in scope for the scan."""
        if self.organization:
            return [self.organization.slug]
        return [org.slug for org in self.organizations]


class FlyOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Fly.io scans."""

    def __init__(self, arguments, bulk_checks_metadata, identity: FlyIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            org_fragment = (
                identity.organization.slug if identity.organization else "fly"
            )
            self.output_filename = (
                f"prowler-output-{org_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
