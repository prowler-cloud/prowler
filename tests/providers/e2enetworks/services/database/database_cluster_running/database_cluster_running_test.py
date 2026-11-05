from unittest import mock

from prowler.providers.e2enetworks.services.database.database_service import (
    DatabaseCluster,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.database.database_cluster_running.database_cluster_running.database_client"


class Test_database_cluster_running:
    def test_no_clusters(self):
        client = mock.MagicMock()
        client.clusters = []
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_cluster_running.database_cluster_running import (
                database_cluster_running,
            )

            assert database_cluster_running().execute() == []

    def test_database_cluster_running_compliant(self):
        client = mock.MagicMock()
        client.clusters = [
            DatabaseCluster(id="1", name="ok", location="Delhi", status="RUNNING"),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_cluster_running.database_cluster_running import (
                database_cluster_running,
            )

            findings = database_cluster_running().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_database_cluster_running_non_compliant(self):
        client = mock.MagicMock()
        client.clusters = [
            DatabaseCluster(id="2", name="bad", location="Delhi", status="STOPPED"),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_cluster_running.database_cluster_running import (
                database_cluster_running,
            )

            findings = database_cluster_running().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
