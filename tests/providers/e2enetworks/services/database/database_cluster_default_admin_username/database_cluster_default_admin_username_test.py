from unittest import mock

from prowler.providers.e2enetworks.services.database.database_service import (
    DatabaseCluster,
)
from tests.providers.e2enetworks.e2enetworks_fixtures import (
    set_mocked_e2enetworks_provider,
)

CLIENT_PATH = "prowler.providers.e2enetworks.services.database.database_cluster_default_admin_username.database_cluster_default_admin_username.database_client"


class Test_database_cluster_default_admin_username:
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
            from prowler.providers.e2enetworks.services.database.database_cluster_default_admin_username.database_cluster_default_admin_username import (
                database_cluster_default_admin_username,
            )

            assert database_cluster_default_admin_username().execute() == []

    def test_database_cluster_default_admin_username_compliant(self):
        client = mock.MagicMock()
        client.clusters = [
            DatabaseCluster(
                id="1", name="ok", location="Delhi", master_username="dbadmin"
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_cluster_default_admin_username.database_cluster_default_admin_username import (
                database_cluster_default_admin_username,
            )

            findings = database_cluster_default_admin_username().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"

    def test_database_cluster_default_admin_username_non_compliant(self):
        client = mock.MagicMock()
        client.clusters = [
            DatabaseCluster(
                id="2", name="bad", location="Delhi", master_username="admin"
            ),
        ]
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2enetworks_provider(),
            ),
            mock.patch(CLIENT_PATH, new=client),
        ):
            from prowler.providers.e2enetworks.services.database.database_cluster_default_admin_username.database_cluster_default_admin_username import (
                database_cluster_default_admin_username,
            )

            findings = database_cluster_default_admin_username().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
