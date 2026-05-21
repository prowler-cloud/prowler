from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


@dataclass
class OCICredentials:
    """OCI Credentials model"""

    user: str
    fingerprint: str
    key_file: Optional[str]
    key_content: Optional[str]
    tenancy: str
    region: str
    pass_phrase: Optional[str] = None


@dataclass
class OCIIdentityInfo:
    """OCI Identity Information model"""

    tenancy_id: str
    tenancy_name: str
    user_id: str
    region: str
    profile: Optional[str]
    audited_regions: set
    audited_compartments: list


@dataclass
class OCICompartment:
    """OCI Compartment model"""

    id: str
    name: str
    lifecycle_state: str
    time_created: datetime
    description: Optional[str] = None
    freeform_tags: Optional[dict] = None
    defined_tags: Optional[dict] = None


@dataclass
class OCISession:
    """OCI Session model to store configuration and signer"""

    config: dict
    signer: object
    profile: Optional[str] = None


@dataclass
class OCIRegion:
    """OCI Region model"""

    key: str
    name: str
    is_home_region: bool = False


@dataclass
class OCIRegionalClient:
    """OCI Regional Client wrapper model"""

    client: object
    region: str


class OCIOutputOptions(ProviderOutputOptions):
    """OCI Output Options model"""

    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call Provider_Output_Options init
        super().__init__(arguments, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            # Use tenancy name if available, otherwise fall back to tenancy ID
            tenancy_identifier = (
                identity.tenancy_name
                if identity.tenancy_name and identity.tenancy_name != "unknown"
                else identity.tenancy_id
            )
            self.output_filename = (
                f"prowler-output-{tenancy_identifier}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
