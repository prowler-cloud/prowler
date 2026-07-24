from unittest import mock
from unittest.mock import MagicMock

from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.configuration."
    "configuration_remote_os_authentication_disabled."
    "configuration_remote_os_authentication_disabled.configuration_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.configuration.configuration_remote_os_authentication_disabled.configuration_remote_os_authentication_disabled import (
            configuration_remote_os_authentication_disabled,
        )

        return configuration_remote_os_authentication_disabled().execute()


def _build_client(parameters=None):
    client = MagicMock()
    client.database_name = ORACLEDB_DATABASE_NAME
    client.parameters = parameters if parameters is not None else {}
    return client


class Test_configuration_remote_os_authentication_disabled:
    def test_no_findings_when_parameters_unreadable(self):
        assert _run_check(_build_client()) == []

    def test_pass(self):
        findings = _run_check(_build_client(parameters={"remote_os_authent": "FALSE"}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_name == "remote_os_authent"
        assert findings[0].resource_id == f"{ORACLEDB_DATABASE_NAME}/remote_os_authent"

    def test_fail(self):
        findings = _run_check(_build_client(parameters={"remote_os_authent": "TRUE"}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "REMOTE_OS_AUTHENT=TRUE" in findings[0].status_extended

    def test_pass_when_parameter_absent(self):
        findings = _run_check(_build_client(parameters={"other_parameter": "VALUE"}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
