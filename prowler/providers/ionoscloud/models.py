from typing import Optional

from pydantic.v1 import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class IonosCloudCredentials(BaseModel):
    """IONOS Cloud credentials."""

    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None


class IonosCloudIdentityInfo(BaseModel):
    """IONOS Cloud identity information."""

    user_id: str
    user_email: str
    contracts: list = []


class IonosCloudOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.user_email}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
