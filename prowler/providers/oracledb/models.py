from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class OracledbSession(BaseModel):
    """Holds the live python-oracledb connection plus the non-secret
    connection coordinates. The password is intentionally not stored —
    services only need the already-authenticated connection object."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    user: str
    dsn: str
    # python-oracledb Connection; Any so pydantic does not try to validate it.
    connection: Any


class OracledbIdentityInfo(BaseModel):
    user: str
    dsn: str
    # Database global name (GLOBAL_NAME view), e.g. ORCL.EXAMPLE.COM. Used as
    # the account UID in outputs and as the mutelist account key.
    database_name: str
    # Full version string from PRODUCT_COMPONENT_VERSION; empty when the
    # connected user cannot query it.
    version: Optional[str] = ""


class OracledbOutputOptions(ProviderOutputOptions):
    def __init__(self, arguments, bulk_checks_metadata, identity):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.database_name}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
