from typing import Any, Optional

from pydantic.v1 import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class LovableSession(BaseModel):
    """Authenticated Lovable session."""

    api_token: str = Field(..., min_length=1)
    workspace_id: Optional[str] = None
    base_url: str = "https://api.lovable.dev/v1"
    http_session: Any = Field(default=None, exclude=True)

    class Config:
        arbitrary_types_allowed = True


class LovableWorkspaceInfo(BaseModel):
    """Lovable workspace metadata."""

    id: str
    name: str = ""
    slug: str = ""
    plan: Optional[str] = None


class LovableIdentityInfo(BaseModel):
    """Lovable identity returned by /v1/me."""

    user_id: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    workspace: Optional[LovableWorkspaceInfo] = None
    workspaces: list[LovableWorkspaceInfo] = Field(default_factory=list)


class LovableOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Lovable scans."""

    def __init__(self, arguments, bulk_checks_metadata, identity: LovableIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            scope = (
                identity.workspace.slug
                if identity.workspace
                else identity.username or "lovable"
            )
            self.output_filename = f"prowler-output-{scope}-{output_file_timestamp}"
        else:
            self.output_filename = arguments.output_filename
