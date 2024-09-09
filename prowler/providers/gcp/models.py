from typing import Optional

from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class GCPIdentityInfo(BaseModel):
    profile: str


class GCPOrganization(BaseModel):
    id: str
    name: str
    # TODO: the name needs to be retrieved from another API
    display_name: Optional[str]


class GCPProject(BaseModel):
    number: str
    id: str
    name: str
    organization: Optional[GCPOrganization]
    labels: dict
    lifecycle_state: str


class GCPOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call ProviderOutputOptions init
        super().__init__(arguments, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.profile}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
