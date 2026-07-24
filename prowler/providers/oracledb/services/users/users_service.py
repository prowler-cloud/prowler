from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.oracledb.lib.service.service import OracledbService
from prowler.providers.oracledb.oracledb_provider import OracledbProvider

# Sample schema accounts shipped with Oracle Database and its demo scripts
# (DBSAT finding USER.SAMPLE). They use well-known passwords and objects and
# must not exist in a production database.
SAMPLE_SCHEMAS = frozenset(
    {"SCOTT", "HR", "OE", "SH", "PM", "IX", "BI", "ADAMS", "BLAKE", "CLARK", "JONES"}
)

# Profile password/resource settings the user checks evaluate.
PROFILE_RESOURCES = (
    "PASSWORD_LIFE_TIME",
    "FAILED_LOGIN_ATTEMPTS",
    "INACTIVE_ACCOUNT_TIME",
    "PASSWORD_VERIFY_FUNCTION",
)


class Users(OracledbService):
    """Oracle Database users and profiles service.

    Reads DBA_USERS and DBA_PROFILES and resolves each user's effective
    password management settings through its profile, mirroring the user
    account findings of the Oracle Database Security Assessment Tool (DBSAT).
    """

    def __init__(self, provider: OracledbProvider):
        super().__init__(__class__.__name__, provider)
        self.profiles = self._list_profiles()
        self.users = self._list_users()

    def _list_profiles(self) -> dict:
        """Read the password/resource limits of every profile.

        Returns:
            dict: {profile_name: {resource_name: limit}}
        """
        logger.info("Users - Listing Oracle Database profiles...")
        profiles = {}
        try:
            in_list = ", ".join(f"'{resource}'" for resource in PROFILE_RESOURCES)
            rows = self._execute_query(
                "SELECT profile, resource_name, limit FROM dba_profiles "
                f"WHERE resource_name IN ({in_list})"
            )
            for profile, resource_name, limit in rows:
                profiles.setdefault(profile, {})[resource_name] = limit
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return profiles

    def _effective_limit(self, profile: str, resource_name: str) -> Optional[str]:
        """Resolve a profile limit, following DEFAULT indirection.

        A profile setting of ``DEFAULT`` inherits the value of the DEFAULT
        profile, which is how Oracle resolves it at authentication time.
        """
        value = self.profiles.get(profile, {}).get(resource_name)
        if value == "DEFAULT" and profile != "DEFAULT":
            value = self.profiles.get("DEFAULT", {}).get(resource_name)
        return value

    def _list_users(self) -> list["User"]:
        """List database users with their effective profile settings.

        ORACLE_MAINTAINED exists since Oracle Database 12.1, the oldest
        release python-oracledb thin mode can connect to, so the column is
        always available.
        """
        logger.info("Users - Listing Oracle Database users...")
        users = []
        try:
            rows = self._execute_query(
                "SELECT username, account_status, profile, default_tablespace, "
                "oracle_maintained FROM dba_users"
            )
            for (
                username,
                account_status,
                profile,
                default_tablespace,
                oracle_maintained,
            ) in rows:
                users.append(
                    User(
                        name=username,
                        account_status=account_status or "",
                        profile=profile or "",
                        default_tablespace=default_tablespace or "",
                        oracle_maintained=oracle_maintained == "Y",
                        password_life_time=self._effective_limit(
                            profile, "PASSWORD_LIFE_TIME"
                        ),
                        failed_login_attempts=self._effective_limit(
                            profile, "FAILED_LOGIN_ATTEMPTS"
                        ),
                        inactive_account_time=self._effective_limit(
                            profile, "INACTIVE_ACCOUNT_TIME"
                        ),
                        password_verify_function=self._effective_limit(
                            profile, "PASSWORD_VERIFY_FUNCTION"
                        ),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        logger.info(f"Found {len(users)} Oracle Database users")
        return users


class User(BaseModel):
    """Oracle Database user model with effective profile limits."""

    name: str
    account_status: str
    profile: str
    default_tablespace: str = ""
    oracle_maintained: bool = False
    password_life_time: Optional[str] = None
    failed_login_attempts: Optional[str] = None
    inactive_account_time: Optional[str] = None
    password_verify_function: Optional[str] = None

    @property
    def is_open(self) -> bool:
        return self.account_status.startswith("OPEN")
