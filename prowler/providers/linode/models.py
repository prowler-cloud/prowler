from typing import Any, Optional

from pydantic import BaseModel

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class LinodeSession(BaseModel):
    """Linode session information."""

    client: Any
    token: Optional[str] = None


class LinodeIdentityInfo(BaseModel):
    """Linode identity and scoping information."""

    username: Optional[str] = None
    email: Optional[str] = None
    account_id: Optional[str] = None


class LinodeOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Linode scans."""

    def __init__(self, arguments, bulk_checks_metadata, identity: LinodeIdentityInfo):
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = identity.account_id or identity.username or "linode"
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
