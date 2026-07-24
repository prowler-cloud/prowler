from unittest import mock
from unittest.mock import MagicMock

from prowler.providers.oracledb.services.users.users_service import User
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.users."
    "users_sample_schemas_removed."
    "users_sample_schemas_removed.users_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.users.users_sample_schemas_removed.users_sample_schemas_removed import (
            users_sample_schemas_removed,
        )

        return users_sample_schemas_removed().execute()


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


class Test_users_sample_schemas_removed:
    def test_pass_when_no_sample_schemas(self):
        findings = _run_check(_build_client([_user()]))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == ORACLEDB_DATABASE_NAME
        assert "no sample" in findings[0].status_extended

    def test_fail_when_sample_schemas_present(self):
        findings = _run_check(
            _build_client([_user(name="SCOTT"), _user(name="HR"), _user()])
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "HR, SCOTT" in findings[0].status_extended

    def test_single_report_even_without_users(self):
        findings = _run_check(_build_client())
        assert len(findings) == 1
        assert findings[0].status == "PASS"
