import re
from typing import List, Optional

from pydantic.v1 import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


def _is_uuid(value: str) -> bool:
    """Check if a string is a valid UUID.

    Accepts both formats:
    - Standard with dashes: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    - Compact without dashes: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    """
    # Standard UUID format with dashes
    uuid_with_dashes = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    # Compact UUID format without dashes (e.g., OVH)
    uuid_without_dashes = re.compile(
        r"^[0-9a-f]{32}$",
        re.IGNORECASE,
    )
    return bool(uuid_with_dashes.match(value) or uuid_without_dashes.match(value))


class OpenStackSession(BaseModel):
    """Holds the authentication/session data used to talk with OpenStack."""

    auth_url: str
    identity_api_version: str = Field(default="3")
    username: str
    password: str
    project_id: str
    region_name: Optional[str] = None
    regions: Optional[List[str]] = None
    user_domain_name: str = Field(default="Default")
    project_domain_name: str = Field(default="Default")

    def as_sdk_config(self, region_override: Optional[str] = None) -> dict:
        """Return a dict compatible with openstacksdk.connect().

        Note: The OpenStack SDK distinguishes between project_id (must be UUID)
        and project_name (any string identifier). We accept project_id from users
        but internally pass it as project_name to the SDK if it's not a UUID.
        This allows compatibility with providers like OVH that use numeric IDs.

        When ``regions`` is set (multi-region), we pass the first region as
        ``region_name`` for the default connection.  The SDK does **not**
        iterate over a ``regions`` list automatically — callers must create
        one connection per region via ``regional_connections``.

        Args:
            region_override: If provided, use this region instead of the
                session's ``region_name`` / first entry in ``regions``.
        """
        config = {
            "auth_url": self.auth_url,
            "username": self.username,
            "password": self.password,
            "project_domain_name": self.project_domain_name,
            "user_domain_name": self.user_domain_name,
            "identity_api_version": self.identity_api_version,
        }
        # Determine region: explicit override > session region_name > first in regions list
        region = region_override or self.region_name
        if region:
            config["region_name"] = region
        elif self.regions:
            config["region_name"] = self.regions[0]
        # If project_id is a UUID, pass it as project_id to SDK
        # Otherwise, pass it as project_name (e.g., OVH numeric IDs)
        if _is_uuid(self.project_id):
            config["project_id"] = self.project_id
        else:
            config["project_name"] = self.project_id
        return config


class OpenStackIdentityInfo(BaseModel):
    """Represents the identity used during the audit run."""

    user_id: Optional[str] = None
    username: str
    project_id: str
    project_name: Optional[str] = None
    region_name: str
    user_domain_name: str
    project_domain_name: str


class OpenStackOutputOptions(ProviderOutputOptions):
    """OpenStack output options."""

    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call ProviderOutputOptions init
        super().__init__(arguments, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            # Use project_name if available, otherwise use project_id
            project_identifier = (
                identity.project_name if identity.project_name else identity.project_id
            )
            self.output_filename = (
                f"prowler-output-{project_identifier}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
