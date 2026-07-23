from unittest import mock
from unittest.mock import MagicMock

from prowler.providers.oracledb.services.encryption.encryption_service import (
    Tablespace,
)
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.encryption."
    "encryption_tablespaces_encrypted."
    "encryption_tablespaces_encrypted.encryption_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.encryption.encryption_tablespaces_encrypted.encryption_tablespaces_encrypted import (
            encryption_tablespaces_encrypted,
        )

        return encryption_tablespaces_encrypted().execute()


def _build_client(wallets=None, tablespaces=None):
    client = MagicMock()
    client.database_name = ORACLEDB_DATABASE_NAME
    client.wallets = wallets or []
    client.tablespaces = tablespaces or []
    return client


class Test_encryption_tablespaces_encrypted:
    def test_no_tablespaces(self):
        assert _run_check(_build_client()) == []

    def test_pass_with_encrypted_tablespace(self):
        tablespace = Tablespace(name="DATA", encrypted=True, contents="PERMANENT")
        findings = _run_check(_build_client(tablespaces=[tablespace]))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == "DATA"
        assert "is encrypted with TDE" in findings[0].status_extended

    def test_fail_with_unencrypted_tablespace(self):
        tablespace = Tablespace(name="DATA", encrypted=False, contents="PERMANENT")
        findings = _run_check(_build_client(tablespaces=[tablespace]))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "is not encrypted with TDE" in findings[0].status_extended

    def test_system_and_transient_tablespaces_are_skipped(self):
        tablespaces = [
            Tablespace(name="SYSTEM", encrypted=False, contents="PERMANENT"),
            Tablespace(name="SYSAUX", encrypted=False, contents="PERMANENT"),
            Tablespace(name="TEMP", encrypted=False, contents="TEMPORARY"),
            Tablespace(name="UNDOTBS1", encrypted=False, contents="UNDO"),
        ]
        assert _run_check(_build_client(tablespaces=tablespaces)) == []
