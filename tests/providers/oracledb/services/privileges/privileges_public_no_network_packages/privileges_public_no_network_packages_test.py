from unittest import mock
from unittest.mock import MagicMock

from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.privileges."
    "privileges_public_no_network_packages."
    "privileges_public_no_network_packages.privileges_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.privileges.privileges_public_no_network_packages.privileges_public_no_network_packages import (
            privileges_public_no_network_packages,
        )

        return privileges_public_no_network_packages().execute()


def _build_client(system_privileges=None, execute_packages=None):
    client = MagicMock()
    client.database_name = ORACLEDB_DATABASE_NAME
    client.public_system_privileges = system_privileges or []
    client.public_execute_packages = execute_packages or []
    return client


class Test_privileges_public_no_network_packages:
    def test_pass_when_no_relevant_packages(self):
        findings = _run_check(
            _build_client(execute_packages=["DBMS_OUTPUT", "DBMS_STANDARD"])
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == ORACLEDB_DATABASE_NAME
        assert "does not grant PUBLIC execute" in findings[0].status_extended

    def test_fail_when_package_is_public(self):
        findings = _run_check(
            _build_client(execute_packages=["DBMS_OUTPUT", "UTL_HTTP"])
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "UTL_HTTP" in findings[0].status_extended
