from unittest import mock
from unittest.mock import MagicMock

from prowler.providers.oracledb.services.encryption.encryption_service import (
    Wallet,
)
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.encryption."
    "encryption_wallet_configured."
    "encryption_wallet_configured.encryption_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.encryption.encryption_wallet_configured.encryption_wallet_configured import (
            encryption_wallet_configured,
        )

        return encryption_wallet_configured().execute()


def _build_client(wallets=None, tablespaces=None):
    client = MagicMock()
    client.database_name = ORACLEDB_DATABASE_NAME
    client.wallets = wallets or []
    client.tablespaces = tablespaces or []
    return client


class Test_encryption_wallet_configured:
    def test_pass_with_open_wallet(self):
        wallet = Wallet(
            wrl_type="FILE",
            wrl_parameter="/opt/oracle/wallet",
            status="OPEN",
            wallet_type="AUTOLOGIN",
        )
        findings = _run_check(_build_client(wallets=[wallet]))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "open TDE keystore" in findings[0].status_extended

    def test_fail_with_closed_wallet(self):
        wallet = Wallet(wrl_type="FILE", status="CLOSED", wallet_type="UNKNOWN")
        findings = _run_check(_build_client(wallets=[wallet]))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "CLOSED" in findings[0].status_extended

    def test_fail_without_wallets(self):
        findings = _run_check(_build_client())
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "NOT_AVAILABLE" in findings[0].status_extended
