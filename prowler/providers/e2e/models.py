from typing import Any

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions

E2E_DEFAULT_LOCATIONS = ("Delhi", "Chennai")
E2E_BASE_URL = "https://api.e2enetworks.com/myaccount/api/v1"


class E2eSession(BaseModel):
    """E2E Cloud API session information."""

    api_key: str = Field(exclude=True, repr=False)
    auth_token: str = Field(exclude=True, repr=False)
    project_id: int
    locations: list[str]
    base_url: str = E2E_BASE_URL
    http_session: Any = Field(default=None, exclude=True)


class E2eIdentityInfo(BaseModel):
    """E2E Cloud identity and scoping information."""

    project_id: int
    locations: list[str]


class E2eOutputOptions(ProviderOutputOptions):
    """Customize output filenames for E2E Cloud scans."""

    def __init__(
        self,
        arguments: object,
        bulk_checks_metadata: dict,
        identity: E2eIdentityInfo,
    ) -> None:
        """Initialize E2E Cloud output options.

        Args:
            arguments: Parsed CLI arguments for the scan.
            bulk_checks_metadata: Loaded metadata for all checks in the scan.
            identity: E2E Cloud identity information used in output filenames.
        """
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-e2e-{identity.project_id}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
