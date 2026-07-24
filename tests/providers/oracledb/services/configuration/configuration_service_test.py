from prowler.providers.oracledb.models import OracledbSession
from prowler.providers.oracledb.services.configuration.configuration_service import (
    Configuration,
)
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DSN,
    ORACLEDB_USER,
    set_mocked_connection,
    set_mocked_oracledb_provider,
)


def _build_configuration_service(fetchall_results):
    provider = set_mocked_oracledb_provider(
        session=OracledbSession(
            user=ORACLEDB_USER,
            dsn=ORACLEDB_DSN,
            connection=set_mocked_connection(fetchall_results=fetchall_results),
        )
    )
    return Configuration(provider)


class TestConfigurationService:
    def test_reads_security_parameters(self):
        service = _build_configuration_service(
            [
                [
                    ("o7_dictionary_accessibility", "FALSE"),
                    ("sql92_security", "TRUE"),
                    ("remote_login_passwordfile", "EXCLUSIVE"),
                    ("sec_return_server_release_banner", "FALSE"),
                ]
            ]
        )

        assert service.parameters == {
            "o7_dictionary_accessibility": "FALSE",
            "sql92_security": "TRUE",
            "remote_login_passwordfile": "EXCLUSIVE",
            "sec_return_server_release_banner": "FALSE",
        }

    def test_query_error_returns_empty(self):
        service = _build_configuration_service(
            [Exception("ORA-00942: table or view does not exist")]
        )

        assert service.parameters == {}
