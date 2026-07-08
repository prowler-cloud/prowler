from unittest import mock
from unittest.mock import MagicMock

from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.privileges."
    "privileges_public_no_system_privileges."
    "privileges_public_no_system_privileges.privileges_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.privileges.privileges_public_no_system_privileges.privileges_public_no_system_privileges import (
            privileges_public_no_system_privileges,
        )

        return privileges_public_no_system_privileges().execute()


def _build_client(system_privileges=None, execute_packages=None):
    client = MagicMock()
    client.database_name = ORACLEDB_DATABASE_NAME
    client.public_system_privileges = system_privileges or []
    client.public_execute_packages = execute_packages or []
    return client


class Test_privileges_public_no_system_privileges:
    def test_pass_when_no_grants(self):
        findings = _run_check(_build_client())
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == ORACLEDB_DATABASE_NAME
        assert "does not grant" in findings[0].status_extended

    def test_fail_when_public_has_system_privileges(self):
        findings = _run_check(
            _build_client(system_privileges=["CREATE TABLE", "SELECT ANY TABLE"])
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "CREATE TABLE, SELECT ANY TABLE" in findings[0].status_extended
