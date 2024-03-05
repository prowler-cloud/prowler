from dataclasses import dataclass

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


@dataclass
class GCPIdentityInfo:
    profile: str
    default_project_id: str


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
