from typing import Any, Optional

from pydantic import BaseModel, Field

from prowler.config.config import output_file_timestamp
from prowler.providers.common.models import ProviderOutputOptions


class SnowflakeSession(BaseModel):
    """Snowflake session information.

    Snowflake key-pair authentication has no token endpoint: the credential *is* the
    private key, and a short-lived JWT is signed per request. ``client`` therefore holds
    the loaded key rather than an access token.
    """

    account: str
    user: str
    # Excluded from serialization, not merely from __repr__. The client holds the
    # RSA private key, so model_dump(), model_dump_json() and dict(session) would
    # each publish the whole credential -- and an output pipeline reaches for
    # those long before anyone prints the object.
    client: Any = Field(default=None, exclude=True)
    role: Optional[str] = None
    warehouse: Optional[str] = None

    def __iter__(self):
        """Iterate the session without the client.

        ``Field(exclude=True)`` governs ``model_dump`` and ``model_dump_json`` but not
        model iteration, so ``dict(session)`` would still hand out the object holding
        the private key. Closing that path too.

        Yields:
            tuple: Each field name and value except ``client``.
        """
        for key, value in super().__iter__():
            if key != "client":
                yield key, value

    def __repr__(self) -> str:
        """Never print the client.

        Pydantic prints every field by default, and the client holds the RSA private
        key, so an unguarded session in a traceback would publish the whole credential.
        """
        return (
            f"SnowflakeSession(account={self.account!r}, user={self.user!r}, "
            f"client=***, role={self.role!r}, warehouse={self.warehouse!r})"
        )

    __str__ = __repr__


class SnowflakeIdentityInfo(BaseModel):
    """Snowflake identity and scoping information."""

    account: Optional[str] = None
    account_locator: Optional[str] = None
    region: Optional[str] = None
    user: Optional[str] = None
    role: Optional[str] = None
    warehouse: Optional[str] = None


class SnowflakeOutputOptions(ProviderOutputOptions):
    """Customize output filenames for Snowflake scans."""

    def __init__(
        self,
        arguments: Any,
        bulk_checks_metadata: dict,
        identity: SnowflakeIdentityInfo,
    ) -> None:
        """Initialize the Snowflake output options.

        Args:
            arguments: The parsed CLI arguments.
            bulk_checks_metadata: The metadata of every loaded check.
            identity: The Snowflake identity the scan is running under.
        """
        super().__init__(arguments, bulk_checks_metadata)
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            account_fragment = (
                identity.account or identity.account_locator or "snowflake"
            )
            self.output_filename = (
                f"prowler-output-{account_fragment}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename
