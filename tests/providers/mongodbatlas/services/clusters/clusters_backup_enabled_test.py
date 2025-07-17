from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.services.clusters.clusters_service import Cluster
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    CLUSTER_ID,
    CLUSTER_NAME,
    CLUSTER_TYPE,
    MONGO_VERSION,
    PROJECT_ID,
    PROJECT_NAME,
    STATE_NAME,
    set_mocked_mongodbatlas_provider,
)


class TestClustersBackupEnabled:
    def _create_cluster(self, backup_enabled=False):
        """Helper method to create a cluster with backup settings"""
        return Cluster(
            id=CLUSTER_ID,
            name=CLUSTER_NAME,
            project_id=PROJECT_ID,
            project_name=PROJECT_NAME,
            mongo_db_version=MONGO_VERSION,
            cluster_type=CLUSTER_TYPE,
            state_name=STATE_NAME,
            auth_enabled=False,
            ssl_enabled=False,
            backup_enabled=backup_enabled,
            encryption_at_rest_provider=None,
            provider_settings={},
            replication_specs=[],
        )

    def _execute_check_with_cluster(self, cluster):
        """Helper method to execute check with a cluster"""
        clusters_client = MagicMock()
        clusters_client.clusters = {f"{PROJECT_ID}:{CLUSTER_NAME}": cluster}

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_backup_enabled.clusters_backup_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_backup_enabled.clusters_backup_enabled import (
                clusters_backup_enabled,
            )

            check = clusters_backup_enabled()
            return check.execute()

    def test_check_with_backup_enabled(self):
        """Test check with backup enabled"""
        cluster = self._create_cluster(backup_enabled=True)
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert "has backup enabled" in reports[0].status_extended

    def test_check_with_backup_disabled(self):
        """Test check with backup disabled"""
        cluster = self._create_cluster(backup_enabled=False)
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "does not have backup enabled" in reports[0].status_extended
