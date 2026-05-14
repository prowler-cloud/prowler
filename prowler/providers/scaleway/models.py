from typing import Any, Literal, Optional

from pydantic.v1 import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions

ScalewayBearerType = Literal["user", "application"]


class ScalewaySession(BaseModel):
    """Scaleway API session information.

    Stores the credentials and the underlying ``scaleway.Client`` so every
    service can reuse the same authenticated client.
    """

    access_key: str
    secret_key: str
    organization_id: Optional[str] = None
    default_project_id: Optional[str] = None
    default_region: Optional[str] = None
    client: Any = Field(default=None, exclude=True)

    class Config:
        arbitrary_types_allowed = True


class ScalewayIdentityInfo(BaseModel):
    """Scaleway identity and scoping information."""

    organization_id: str
    bearer_id: Optional[str] = None
    bearer_type: Optional[ScalewayBearerType] = None
    bearer_email: Optional[str] = None
    account_root_user_id: Optional[str] = None


class ScalewayOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Scaleway scans."""

    def __init__(self, arguments, bulk_checks_metadata, identity: ScalewayIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = identity.organization_id or "scaleway"
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
