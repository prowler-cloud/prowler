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


class TestClustersEncryptionAtRestEnabled:
    def _create_cluster(
        self, encryption_at_rest_provider=None, paused=False, provider_settings=None
    ):
        """Helper method to create a cluster with encryption settings"""
        if provider_settings is None:
            provider_settings = {}

        return Cluster(
            id=CLUSTER_ID,
            name=CLUSTER_NAME,
            project_id=PROJECT_ID,
            project_name=PROJECT_NAME,
            mongo_db_version=MONGO_VERSION,
            cluster_type=CLUSTER_TYPE,
            state_name=STATE_NAME,
            encryption_at_rest_provider=encryption_at_rest_provider,
            backup_enabled=False,
            provider_settings=provider_settings,
            replication_specs=[],
            paused=paused,
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
                "prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled.clusters_client",
                new=clusters_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.clusters.clusters_encryption_at_rest_enabled.clusters_encryption_at_rest_enabled import (
                clusters_encryption_at_rest_enabled,
            )

            check = clusters_encryption_at_rest_enabled()
            return check.execute()

    def test_check_with_aws_encryption_provider(self):
        """Test check with AWS encryption provider"""
        cluster = self._create_cluster(encryption_at_rest_provider="AWS")
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "encryption at rest enabled with provider: AWS"
            in reports[0].status_extended
        )

    def test_check_with_azure_encryption_provider(self):
        """Test check with Azure encryption provider"""
        cluster = self._create_cluster(encryption_at_rest_provider="AZURE")
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "encryption at rest enabled with provider: AZURE"
            in reports[0].status_extended
        )

    def test_check_with_gcp_encryption_provider(self):
        """Test check with GCP encryption provider"""
        cluster = self._create_cluster(encryption_at_rest_provider="GCP")
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "encryption at rest enabled with provider: GCP"
            in reports[0].status_extended
        )

    def test_check_with_none_encryption_provider(self):
        """Test check with NONE encryption provider"""
        cluster = self._create_cluster(encryption_at_rest_provider="NONE")
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "encryption at rest explicitly disabled" in reports[0].status_extended

    def test_check_with_unsupported_encryption_provider(self):
        """Test check with unsupported encryption provider"""
        cluster = self._create_cluster(encryption_at_rest_provider="UNSUPPORTED")
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "unsupported encryption provider" in reports[0].status_extended

    def test_check_with_no_encryption_provider_but_ebs_encryption(self):
        """Test check with no encryption provider but EBS encryption enabled"""
        cluster = self._create_cluster(
            encryption_at_rest_provider=None,
            provider_settings={"encryptEBSVolume": True},
        )
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert "EBS volume encryption enabled" in reports[0].status_extended

    def test_check_with_no_encryption(self):
        """Test check with no encryption at all"""
        cluster = self._create_cluster(
            encryption_at_rest_provider=None,
            provider_settings={"encryptEBSVolume": False},
        )
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "does not have encryption at rest enabled" in reports[0].status_extended

    def test_check_with_paused_cluster(self):
        """Test check with paused cluster"""
        cluster = self._create_cluster(
            encryption_at_rest_provider=None, paused=True, provider_settings={}
        )
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert "is paused" in reports[0].status_extended
        assert "encryption at rest check skipped" in reports[0].status_extended

    def test_check_with_empty_provider_settings(self):
        """Test check with empty provider settings"""
        cluster = self._create_cluster(
            encryption_at_rest_provider=None, provider_settings=None
        )
        reports = self._execute_check_with_cluster(cluster)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "does not have encryption at rest enabled" in reports[0].status_extended
