from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.snowflake.lib.service.service import SnowflakeService
from prowler.providers.snowflake.snowflake_provider import SnowflakeProvider

# Every column the checks read, listed explicitly rather than SELECT *: ACCOUNT_USAGE
# views gain columns over time, and naming them keeps a new upstream column from
# silently changing what is parsed here.
#
# Deleted users are excluded. They cannot sign in, so reporting them is noise.
#
# There is deliberately no LIMIT. ACCOUNT_USAGE.USERS is one row per user and a capped
# query would silently under-report on a large account -- and because the ordering that
# would accompany a cap is by creation date, the rows dropped would be the oldest, which
# is exactly where long-standing unprotected accounts live.
USERS_QUERY = (
    "SELECT NAME, DISABLED, HAS_PASSWORD, HAS_RSA_PUBLIC_KEY, EXT_AUTHN_DUO, "
    "HAS_MFA, BYPASS_MFA_UNTIL, DEFAULT_ROLE, TYPE, LAST_SUCCESS_LOGIN, CREATED_ON "
    "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS "
    "WHERE DELETED_ON IS NULL"
)


def _as_bool(value) -> bool:
    """Coerce a SQL API value to a boolean.

    The SQL API returns every column as a string, so a false boolean arrives as
    ``"false"`` -- which is truthy in Python. Anything not recognised as true is treated
    as false.

    Args:
        value: The raw column value.

    Returns:
        bool: The coerced value.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("true", "t", "1", "yes", "y")


def _as_datetime(value) -> Optional[datetime]:
    """Parse a timestamp column into a timezone-aware datetime.

    Args:
        value: The raw column value.

    Returns:
        Optional[datetime]: The parsed timestamp, or None if absent or unparseable.
    """
    if not value:
        return None
    text = str(value).strip()
    try:
        # The SQL API renders TIMESTAMP_LTZ as epoch seconds with a fractional part.
        if text.replace(".", "", 1).replace("-", "", 1).isdigit():
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


class User(BaseModel):
    """A Snowflake user as reported by ACCOUNT_USAGE.USERS."""

    name: str
    disabled: bool = False
    has_password: bool = False
    has_rsa_public_key: bool = False
    ext_authn_duo: bool = False
    has_mfa: bool = False
    bypass_mfa_until: Optional[datetime] = None
    default_role: Optional[str] = None
    type: Optional[str] = None
    last_success_login: Optional[datetime] = None
    created_on: Optional[datetime] = None

    @property
    def mfa_enrolled(self) -> bool:
        """Whether the user is enrolled in any supported MFA method.

        ``EXT_AUTHN_DUO`` is the legacy column and remains the only signal for an
        account that enrolled through Duo; ``HAS_MFA`` is what Snowflake sets for its
        native MFA. Both are read, because keying on Duo alone reports every user on a
        modern method as unprotected.
        """
        return self.has_mfa or self.ext_authn_duo

    @property
    def mfa_bypassed(self) -> bool:
        """Whether an MFA bypass window is currently open for this user.

        ``BYPASS_MFA_UNTIL`` is a timestamp, so a value in the future means the user can
        sign in with a password alone right now regardless of enrolment. A value that
        could not be parsed is treated as *not* bypassed: this decides whether to raise a
        finding, and inventing one from a value that could not be read would be a false
        positive against a user who may well be protected.
        """
        if self.bypass_mfa_until is None:
            return False
        return self.bypass_mfa_until > datetime.now(timezone.utc)


class Users(SnowflakeService):
    """Snowflake users service."""

    def __init__(self, provider: SnowflakeProvider):
        """Initialize the users service and load the account's users.

        Args:
            provider: The Snowflake provider instance.
        """
        super().__init__(provider)
        self.users = []
        self._get_users()

    def _get_users(self):
        """Populate ``self.users`` from ACCOUNT_USAGE.USERS.

        Returns:
            None. Appends to ``self.users`` as a side effect.
        """
        try:
            for row in self.client.query(USERS_QUERY):
                self.users.append(
                    User(
                        name=row.get("NAME"),
                        disabled=_as_bool(row.get("DISABLED")),
                        has_password=_as_bool(row.get("HAS_PASSWORD")),
                        has_rsa_public_key=_as_bool(row.get("HAS_RSA_PUBLIC_KEY")),
                        ext_authn_duo=_as_bool(row.get("EXT_AUTHN_DUO")),
                        has_mfa=_as_bool(row.get("HAS_MFA")),
                        bypass_mfa_until=_as_datetime(row.get("BYPASS_MFA_UNTIL")),
                        default_role=row.get("DEFAULT_ROLE"),
                        type=row.get("TYPE"),
                        last_success_login=_as_datetime(row.get("LAST_SUCCESS_LOGIN")),
                        created_on=_as_datetime(row.get("CREATED_ON")),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
