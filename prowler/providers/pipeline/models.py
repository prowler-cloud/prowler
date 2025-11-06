"""Pipeline Provider Models."""

from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class PipelineIdentityInfo(BaseModel):
    """Model for Pipeline Provider Identity Information."""

    platform: str = "unknown"
    organization: str = ""
    repository: str = ""
    scan_type: str = "local"  # local, repository, or organization


class PipelineOutputOptions(ProviderOutputOptions):
    """Output options for the Pipeline provider."""

    def __init__(self, arguments, bulk_checks_metadata=None):
        """Initialize the Pipeline output options."""
        super().__init__(arguments, bulk_checks_metadata)

        # Set default output filename if not specified
        if not getattr(arguments, "output_filename", None):
            self.output_filename = f"prowler-output-pipeline-{output_file_timestamp}"
