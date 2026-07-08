from prowler.providers.oracledb.models import OracledbSession
from prowler.providers.oracledb.services.privileges.privileges_service import (
    Privileges,
)
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DSN,
    ORACLEDB_USER,
    set_mocked_connection,
    set_mocked_oracledb_provider,
)


def _build_privileges_service(fetchall_results):
    provider = set_mocked_oracledb_provider(
        session=OracledbSession(
            user=ORACLEDB_USER,
            dsn=ORACLEDB_DSN,
            connection=set_mocked_connection(fetchall_results=fetchall_results),
        )
    )
    return Privileges(provider)


class TestPrivilegesService:
    def test_lists_public_grants_sorted(self):
        service = _build_privileges_service(
            [
                [("SELECT ANY TABLE",), ("CREATE TABLE",)],
                [("UTL_HTTP",), ("DBMS_CRYPTO",)],
            ]
        )

        assert service.public_system_privileges == [
            "CREATE TABLE",
            "SELECT ANY TABLE",
        ]
        assert service.public_execute_packages == ["DBMS_CRYPTO", "UTL_HTTP"]

    def test_empty_grants(self):
        service = _build_privileges_service([[], []])

        assert service.public_system_privileges == []
        assert service.public_execute_packages == []

    def test_query_error_returns_empty(self):
        service = _build_privileges_service(
            [Exception("ORA-00942: table or view does not exist")] * 2
        )

        assert service.public_system_privileges == []
        assert service.public_execute_packages == []
