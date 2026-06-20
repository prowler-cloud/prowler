from unittest import mock

from prowler.providers.e2e.services.database.database_service import DatabaseCluster
from tests.providers.e2e.e2e_fixtures import set_mocked_e2e_provider


class TestDatabaseClusterSslEnabledCheck:
    def test_pass_and_fail(self):
        database_client = mock.MagicMock()
        database_client.clusters = [
            DatabaseCluster(
                id="1",
                name="secure-db",
                location="Delhi",
                master_ssl_enabled=True,
            ),
            DatabaseCluster(
                id="2",
                name="insecure-db",
                location="Delhi",
                master_ssl_enabled=False,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2e_provider(),
            ),
            mock.patch(
                "prowler.providers.e2e.services.database.database_cluster_ssl_enabled.database_cluster_ssl_enabled.database_client",
                new=database_client,
            ),
        ):
            from prowler.providers.e2e.services.database.database_cluster_ssl_enabled.database_cluster_ssl_enabled import (
                database_cluster_ssl_enabled,
            )

            findings = database_cluster_ssl_enabled().execute()

            assert len(findings) == 2
            assert findings[0].status == "PASS"
            assert findings[1].status == "FAIL"
