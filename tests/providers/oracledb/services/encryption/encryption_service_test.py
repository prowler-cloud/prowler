from prowler.providers.oracledb.models import OracledbSession
from prowler.providers.oracledb.services.encryption.encryption_service import (
    Encryption,
)
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DSN,
    ORACLEDB_USER,
    set_mocked_connection,
    set_mocked_oracledb_provider,
)


def _build_encryption_service(fetchall_results):
    provider = set_mocked_oracledb_provider(
        session=OracledbSession(
            user=ORACLEDB_USER,
            dsn=ORACLEDB_DSN,
            connection=set_mocked_connection(fetchall_results=fetchall_results),
        )
    )
    return Encryption(provider)


class TestEncryptionService:
    def test_lists_wallets_and_tablespaces(self):
        service = _build_encryption_service(
            [
                [("FILE", "/opt/oracle/wallet", "OPEN", "AUTOLOGIN")],
                [
                    ("SYSTEM", "NO", "PERMANENT"),
                    ("DATA", "YES", "PERMANENT"),
                    ("TEMP", "NO", "TEMPORARY"),
                ],
            ]
        )

        assert len(service.wallets) == 1
        assert service.wallets[0].status == "OPEN"
        assert service.wallets[0].wallet_type == "AUTOLOGIN"

        assert len(service.tablespaces) == 3
        data = next(ts for ts in service.tablespaces if ts.name == "DATA")
        assert data.encrypted is True
        assert data.is_user_permanent is True

        system = next(ts for ts in service.tablespaces if ts.name == "SYSTEM")
        assert system.is_user_permanent is False

        temp = next(ts for ts in service.tablespaces if ts.name == "TEMP")
        assert temp.is_user_permanent is False

    def test_query_error_returns_empty(self):
        service = _build_encryption_service(
            [Exception("ORA-00942: table or view does not exist")] * 2
        )

        assert service.wallets == []
        assert service.tablespaces == []
