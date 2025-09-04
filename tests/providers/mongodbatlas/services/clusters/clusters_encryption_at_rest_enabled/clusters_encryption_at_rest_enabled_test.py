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


class Test_clusters_encryption_at_rest_enabled:
    def test_no_clusters(self):
        clusters_client = mock.MagicMock
        clusters_client.clusters = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_clusters_encryption_at_rest_enabled_aws(self):
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
                encryption_at_rest_provider="AWS",
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
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
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} has encryption at rest enabled with provider: AWS."
            )

    def test_clusters_encryption_at_rest_enabled_azure(self):
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
                encryption_at_rest_provider="AZURE",
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
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
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} has encryption at rest enabled with provider: AZURE."
            )

    def test_clusters_encryption_at_rest_enabled_gcp(self):
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
                encryption_at_rest_provider="GCP",
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
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
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} has encryption at rest enabled with provider: GCP."
            )

    def test_clusters_encryption_at_rest_disabled_none(self):
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
                encryption_at_rest_provider="NONE",
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
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
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} has encryption at rest explicitly disabled."
            )

    def test_clusters_encryption_at_rest_unsupported_provider(self):
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
                encryption_at_rest_provider="UNSUPPORTED",
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
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
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} has an unsupported encryption provider: UNSUPPORTED."
            )

    def test_clusters_encryption_at_rest_enabled_ebs(self):
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
                encryption_at_rest_provider=None,
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
                provider_settings={"encryptEBSVolume": True},
                replication_specs=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} has EBS volume encryption enabled."
            )

    def test_clusters_encryption_at_rest_disabled(self):
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
                encryption_at_rest_provider=None,
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
                provider_settings={"encryptEBSVolume": False},
                replication_specs=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} does not have encryption at rest enabled."
            )

    def test_clusters_encryption_at_rest_disabled_empty_settings(self):
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
                encryption_at_rest_provider=None,
                backup_enabled=False,
                auth_enabled=False,
                ssl_enabled=False,
                provider_settings=None,
                replication_specs=[],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            mock.patch(
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == CLUSTER_ID
            assert result[0].resource_name == cluster_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster {cluster_name} in project {project_name} does not have encryption at rest enabled."
            )
