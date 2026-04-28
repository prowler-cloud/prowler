from typing import Optional

from google.oauth2.service_account import Credentials
from pydantic.v1 import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class GoogleWorkspaceSession(BaseModel):
    """Google Workspace session containing credentials"""

    credentials: Credentials

    class Config:
        arbitrary_types_allowed = True


class GoogleWorkspaceIdentityInfo(BaseModel):
    """Google Workspace identity information"""

    domain: str
    customer_id: str
    delegated_user: str
    root_org_unit_id: Optional[str] = None
    profile: Optional[str] = "default"


class GoogleWorkspaceResource(BaseModel):
    """Generic Google Workspace resource used by findings."""

    id: str
    customer_id: str
    location: str = "global"
    name: Optional[str] = None
    email: Optional[str] = None

    @classmethod
    def from_identity(
        cls, identity: "GoogleWorkspaceIdentityInfo"
    ) -> "GoogleWorkspaceResource":
        """Build the domain-level resource from provider identity."""

        return cls(
            id=identity.customer_id,
            name=identity.domain,
            customer_id=identity.customer_id,
        )

    @classmethod
    def from_user(
        cls, user: BaseModel | object, customer_id: str
    ) -> "GoogleWorkspaceResource":
        """Build a user-level resource from a Google Workspace user object."""

        return cls(
            id=getattr(user, "id", ""),
            email=getattr(user, "email", ""),
            customer_id=customer_id,
        )


class GoogleWorkspaceOutputOptions(ProviderOutputOptions):
    """Google Workspace specific output options"""

    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call ProviderOutputOptions init
        super().__init__(arguments, bulk_checks_metadata)
        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.domain}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
