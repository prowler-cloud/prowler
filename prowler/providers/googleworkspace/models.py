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
    profile: Optional[str] = "default"


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
