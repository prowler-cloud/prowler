from prowler.providers.oracledb.models import OracledbSession
from prowler.providers.oracledb.services.users.users_service import Users
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DSN,
    ORACLEDB_USER,
    set_mocked_connection,
    set_mocked_oracledb_provider,
)

PROFILE_ROWS = [
    ("DEFAULT", "PASSWORD_LIFE_TIME", "180"),
    ("DEFAULT", "FAILED_LOGIN_ATTEMPTS", "10"),
    ("DEFAULT", "INACTIVE_ACCOUNT_TIME", "UNLIMITED"),
    ("DEFAULT", "PASSWORD_VERIFY_FUNCTION", "NULL"),
    ("APP_PROFILE", "PASSWORD_LIFE_TIME", "DEFAULT"),
    ("APP_PROFILE", "FAILED_LOGIN_ATTEMPTS", "UNLIMITED"),
    ("APP_PROFILE", "INACTIVE_ACCOUNT_TIME", "30"),
    ("APP_PROFILE", "PASSWORD_VERIFY_FUNCTION", "ORA12C_VERIFY_FUNCTION"),
]

USER_ROWS = [
    ("SYS", "OPEN", "DEFAULT", "SYSTEM", "Y"),
    ("APPUSER", "OPEN", "APP_PROFILE", "USERS", "N"),
    ("OLDUSER", "LOCKED", "DEFAULT", "USERS", "N"),
]


def _build_users_service(fetchall_results):
    provider = set_mocked_oracledb_provider(
        session=OracledbSession(
            user=ORACLEDB_USER,
            dsn=ORACLEDB_DSN,
            connection=set_mocked_connection(fetchall_results=fetchall_results),
        )
    )
    return Users(provider)


class TestUsersService:
    def test_lists_users_with_effective_limits(self):
        service = _build_users_service([PROFILE_ROWS, USER_ROWS])

        assert len(service.users) == 3

        appuser = next(user for user in service.users if user.name == "APPUSER")
        assert appuser.profile == "APP_PROFILE"
        assert appuser.oracle_maintained is False
        assert appuser.is_open is True
        # DEFAULT indirection resolves to the DEFAULT profile value.
        assert appuser.password_life_time == "180"
        assert appuser.failed_login_attempts == "UNLIMITED"
        assert appuser.inactive_account_time == "30"
        assert appuser.password_verify_function == "ORA12C_VERIFY_FUNCTION"

        sys_user = next(user for user in service.users if user.name == "SYS")
        assert sys_user.oracle_maintained is True
        assert sys_user.default_tablespace == "SYSTEM"

        old_user = next(user for user in service.users if user.name == "OLDUSER")
        assert old_user.is_open is False

    def test_profiles_indexed_by_name(self):
        service = _build_users_service([PROFILE_ROWS, USER_ROWS])

        assert service.profiles["DEFAULT"]["PASSWORD_LIFE_TIME"] == "180"
        assert service.profiles["APP_PROFILE"]["PASSWORD_LIFE_TIME"] == "DEFAULT"

    def test_query_error_returns_empty(self):
        service = _build_users_service(
            [Exception("ORA-00942: table or view does not exist")] * 2
        )

        assert service.profiles == {}
        assert service.users == []
