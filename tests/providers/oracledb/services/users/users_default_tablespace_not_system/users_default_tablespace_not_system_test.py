from unittest import mock
from unittest.mock import MagicMock

from prowler.providers.oracledb.services.users.users_service import User
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.users."
    "users_default_tablespace_not_system."
    "users_default_tablespace_not_system.users_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.users.users_default_tablespace_not_system.users_default_tablespace_not_system import (
            users_default_tablespace_not_system,
        )

        return users_default_tablespace_not_system().execute()


def _user(name="APPUSER", **overrides):
    defaults = {
        "name": name,
        "account_status": "OPEN",
        "profile": "DEFAULT",
        "default_tablespace": "USERS",
        "oracle_maintained": False,
        "password_life_time": "180",
        "failed_login_attempts": "10",
        "inactive_account_time": "30",
        "password_verify_function": "ORA12C_VERIFY_FUNCTION",
    }
    defaults.update(overrides)
    return User(**defaults)


def _build_client(users=None):
    client = MagicMock()
    client.database_name = ORACLEDB_DATABASE_NAME
    client.users = users if users is not None else []
    return client


class Test_users_default_tablespace_not_system:
    def test_no_users(self):
        assert _run_check(_build_client()) == []

    def test_pass_with_application_tablespace(self):
        findings = _run_check(_build_client([_user()]))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "USERS" in findings[0].status_extended

    def test_fail_with_system_tablespace(self):
        findings = _run_check(_build_client([_user(default_tablespace="SYSTEM")]))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "reserved tablespace SYSTEM" in findings[0].status_extended

    def test_fail_with_sysaux_tablespace(self):
        findings = _run_check(_build_client([_user(default_tablespace="SYSAUX")]))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"

    def test_oracle_maintained_users_are_skipped(self):
        findings = _run_check(
            _build_client(
                [
                    _user(
                        name="SYS",
                        oracle_maintained=True,
                        default_tablespace="SYSTEM",
                    )
                ]
            )
        )
        assert findings == []
