from typing import Any, Optional

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class VercelSession(BaseModel):
    """Vercel API session information."""

    token: str
    team_id: Optional[str] = None
    base_url: str = "https://api.vercel.com"
    http_session: Any = Field(default=None, exclude=True)


class VercelTeamInfo(BaseModel):
    """Vercel team metadata."""

    id: str
    name: str
    slug: str


class VercelIdentityInfo(BaseModel):
    """Vercel identity and scoping information."""

    user_id: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    team: Optional[VercelTeamInfo] = None
    teams: list[VercelTeamInfo] = Field(default_factory=list)


class VercelOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Vercel scans."""

    def __init__(self, arguments, bulk_checks_metadata, identity: VercelIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = (
                identity.team.slug if identity.team else identity.username or "vercel"
            )
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
