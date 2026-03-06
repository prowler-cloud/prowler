from unittest.mock import MagicMock, patch

# Mock Provider.get_global_provider() before importing clusters_service
with patch(
    "prowler.providers.common.provider.Provider.get_global_provider"
) as mock_get_global_provider:
    mock_provider = MagicMock()
    mock_provider.session = MagicMock()
    mock_provider.session.base_url = "https://cloud.mongodb.com/api/atlas/v1.0"
    mock_provider.audit_config = {}
    mock_get_global_provider.return_value = mock_provider

    from prowler.providers.mongodbatlas.services.clusters.clusters_service import (
        Cluster,
        Clusters,
    )

from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    CLUSTER_ID,
    CLUSTER_NAME,
    CLUSTER_TYPE,
    MONGO_VERSION,
    PROJECT_ID,
    PROJECT_NAME,
    set_mocked_mongodbatlas_provider,
)


def mock_clusters_list_clusters(_):
    return {
        f"{PROJECT_ID}:{CLUSTER_NAME}": Cluster(
            id=CLUSTER_ID,
            name=CLUSTER_NAME,
            project_id=PROJECT_ID,
            project_name=PROJECT_NAME,
            mongo_db_version=MONGO_VERSION,
            cluster_type=CLUSTER_TYPE,
            state_name="IDLE",
            encryption_at_rest_provider="AWS",
            backup_enabled=True,
            auth_enabled=True,
            ssl_enabled=True,
            provider_settings={
                "providerName": "AWS",
                "regionName": "US_EAST_1",
                "encryptEBSVolume": True,
            },
            replication_specs=[
                {
                    "regionConfigs": [
                        {
                            "regionName": "US_EAST_1",
                            "electableSpecs": {"instanceSize": "M10"},
                        }
                    ]
                }
            ],
            disk_size_gb=10.0,
            num_shards=1,
            replication_factor=3,
            auto_scaling={"diskGBEnabled": True},
            mongo_db_major_version="7.0",
            paused=False,
            pit_enabled=True,
            connection_strings={"standard": "mongodb://cluster.mongodb.net"},
            tags=[{"key": "environment", "value": "test"}],
            location="us_east_1",
        )
    }


@patch(
    "prowler.providers.mongodbatlas.services.clusters.clusters_service.Clusters._list_clusters",
    new=mock_clusters_list_clusters,
)
class Test_Clusters_Service:
    def test_get_client(self):
        clusters_service_client = Clusters(set_mocked_mongodbatlas_provider())
        assert clusters_service_client.__class__.__name__ == "Clusters"

    def test_list_clusters(self):
        clusters_service_client = Clusters(set_mocked_mongodbatlas_provider())
        assert len(clusters_service_client.clusters) == 1

        cluster_key = f"{PROJECT_ID}:{CLUSTER_NAME}"
        cluster = clusters_service_client.clusters[cluster_key]

        assert cluster.id == CLUSTER_ID
        assert cluster.name == CLUSTER_NAME
        assert cluster.project_id == PROJECT_ID
        assert cluster.project_name == PROJECT_NAME
        assert cluster.mongo_db_version == MONGO_VERSION
        assert cluster.cluster_type == CLUSTER_TYPE
        assert cluster.state_name == "IDLE"
        assert cluster.encryption_at_rest_provider == "AWS"
        assert cluster.backup_enabled is True
        assert cluster.auth_enabled is True
        assert cluster.ssl_enabled is True
        assert cluster.provider_settings["providerName"] == "AWS"
        assert cluster.provider_settings["regionName"] == "US_EAST_1"
        assert cluster.provider_settings["encryptEBSVolume"] is True
        assert cluster.disk_size_gb == 10.0
        assert cluster.num_shards == 1
        assert cluster.replication_factor == 3
        assert cluster.auto_scaling["diskGBEnabled"] is True
        assert cluster.mongo_db_major_version == "7.0"
        assert cluster.paused is False
        assert cluster.pit_enabled is True
        assert cluster.connection_strings["standard"] == "mongodb://cluster.mongodb.net"
        assert cluster.tags[0]["key"] == "environment"
        assert cluster.tags[0]["value"] == "test"
        assert cluster.location == "us_east_1"
