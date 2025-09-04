from unittest import mock

# Mock Provider.get_global_provider() before importing clusters_service
with mock.patch(
    "prowler.providers.common.provider.Provider.get_global_provider"
) as mock_get_global_provider:
    mock_provider = mock.MagicMock()
    mock_provider.session = mock.MagicMock()
    mock_provider.session.base_url = "https://cloud.mongodb.com/api/atlas/v1.0"
    mock_provider.audit_config = {}
    mock_get_global_provider.return_value = mock_provider

    from prowler.providers.mongodbatlas.services.clusters.clusters_service import (
        Cluster,
    )

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


class Test_clusters_tls_enabled:
    def test_no_clusters(self):
        clusters_client = mock.MagicMock
        clusters_client.clusters = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_tls_enabled.clusters_tls_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_tls_enabled.clusters_tls_enabled import (
                clusters_tls_enabled,
            )

            check = clusters_tls_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_clusters_tls_enabled(self):
        clusters_client = mock.MagicMock
        cluster_name = CLUSTER_NAME
        project_name = PROJECT_NAME
        clusters_client.clusters = {
            f"{PROJECT_ID}:{CLUSTER_NAME}": Cluster(
                id=CLUSTER_ID,
                name=cluster_name,
                project_id=PROJECT_ID,
                project_name=project_name,
                mongo_db_version=MONGO_VERSION,
                cluster_type=CLUSTER_TYPE,
                state_name=STATE_NAME,
                auth_enabled=False,
                ssl_enabled=True,
                backup_enabled=False,
                encryption_at_rest_provider=None,
                provider_settings={},
                replication_specs=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_tls_enabled.clusters_tls_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_tls_enabled.clusters_tls_enabled import (
                clusters_tls_enabled,
            )

            check = clusters_tls_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} has TLS authentication enabled."
            )

    def test_clusters_tls_disabled(self):
        clusters_client = mock.MagicMock
        cluster_name = CLUSTER_NAME
        project_name = PROJECT_NAME
        clusters_client.clusters = {
            f"{PROJECT_ID}:{CLUSTER_NAME}": Cluster(
                id=CLUSTER_ID,
                name=cluster_name,
                project_id=PROJECT_ID,
                project_name=project_name,
                mongo_db_version=MONGO_VERSION,
                cluster_type=CLUSTER_TYPE,
                state_name=STATE_NAME,
                auth_enabled=False,
                ssl_enabled=False,
                backup_enabled=False,
                encryption_at_rest_provider=None,
                provider_settings={},
                replication_specs=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_tls_enabled.clusters_tls_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_tls_enabled.clusters_tls_enabled import (
                clusters_tls_enabled,
            )

            check = clusters_tls_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} does not have TLS authentication enabled."
            )
