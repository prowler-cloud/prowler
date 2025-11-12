from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageBucketDataAccessAuditLogsEnabled:
    def test_no_buckets(self):
        cloudstorage_client = mock.MagicMock()
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider." "get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_data_access_audit_logs_enabled.cloudstorage_bucket_data_access_audit_logs_enabled import (
                cloudstorage_bucket_data_access_audit_logs_enabled,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION
            cloudstorage_client.buckets = []
            cloudresourcemanager_client.cloud_resource_manager_projects = []

            check = cloudstorage_bucket_data_access_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_bucket_with_audit_logs_enabled(self):
        cloudstorage_client = mock.MagicMock()
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider." "get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_data_access_audit_logs_enabled.cloudstorage_bucket_data_access_audit_logs_enabled import (
                cloudstorage_bucket_data_access_audit_logs_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="test-bucket",
                    id="test-bucket",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                )
            ]

            cloudresourcemanager_client.cloud_resource_manager_projects = [
                Project(
                    id=GCP_PROJECT_ID,
                    audit_logging=True,
                    audit_configs=[
                        AuditConfig(
                            service="storage.googleapis.com",
                            log_types=["DATA_READ", "DATA_WRITE"],
                        )
                    ],
                )
            ]

            check = cloudstorage_bucket_data_access_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Bucket test-bucket is covered by project "
                f"{GCP_PROJECT_ID} audit logging with DATA_READ and "
                f"DATA_WRITE enabled."
            )
            assert result[0].resource_id == "test-bucket"
            assert result[0].resource_name == "test-bucket"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_without_audit_logs(self):
        cloudstorage_client = mock.MagicMock()
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider." "get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_data_access_audit_logs_enabled.cloudstorage_bucket_data_access_audit_logs_enabled import (
                cloudstorage_bucket_data_access_audit_logs_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="test-bucket-no-audit",
                    id="test-bucket-no-audit",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                )
            ]

            cloudresourcemanager_client.cloud_resource_manager_projects = [
                Project(
                    id=GCP_PROJECT_ID,
                    audit_logging=False,
                    audit_configs=[],
                )
            ]

            check = cloudstorage_bucket_data_access_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Bucket test-bucket-no-audit is not covered by audit "
                f"logging in project {GCP_PROJECT_ID} (no Cloud Storage "
                f"audit config found)."
            )
            assert result[0].resource_id == "test-bucket-no-audit"
            assert result[0].resource_name == "test-bucket-no-audit"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_missing_log_types(self):
        cloudstorage_client = mock.MagicMock()
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider." "get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_data_access_audit_logs_enabled.cloudstorage_bucket_data_access_audit_logs_enabled import (
                cloudstorage_bucket_data_access_audit_logs_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="test-bucket-incomplete",
                    id="test-bucket-incomplete",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                )
            ]

            cloudresourcemanager_client.cloud_resource_manager_projects = [
                Project(
                    id=GCP_PROJECT_ID,
                    audit_logging=True,
                    audit_configs=[
                        AuditConfig(
                            service="storage.googleapis.com",
                            log_types=["DATA_WRITE"],
                        )
                    ],
                )
            ]

            check = cloudstorage_bucket_data_access_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Bucket test-bucket-incomplete is not fully covered by "
                f"project {GCP_PROJECT_ID} audit logging "
                f"(missing: DATA_READ)."
            )
            assert result[0].resource_id == "test-bucket-incomplete"
            assert result[0].resource_name == "test-bucket-incomplete"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_combined_audit_configs(self):
        cloudstorage_client = mock.MagicMock()
        cloudresourcemanager_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider." "get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_client",
                new=cloudstorage_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudstorage_bucket_data_access_audit_logs_enabled."
                "cloudresourcemanager_client",
                new=cloudresourcemanager_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
                AuditConfig,
                Project,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_data_access_audit_logs_enabled.cloudstorage_bucket_data_access_audit_logs_enabled import (
                cloudstorage_bucket_data_access_audit_logs_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="test-bucket-combined",
                    id="test-bucket-combined",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                    versioning_enabled=True,
                )
            ]

            # Project has both allServices (with DATA_READ)
            # and storage.googleapis.com (with DATA_WRITE)
            cloudresourcemanager_client.cloud_resource_manager_projects = [
                Project(
                    id=GCP_PROJECT_ID,
                    audit_logging=True,
                    audit_configs=[
                        AuditConfig(
                            service="allServices",
                            log_types=["DATA_READ"],
                        ),
                        AuditConfig(
                            service="storage.googleapis.com",
                            log_types=["DATA_WRITE"],
                        ),
                    ],
                )
            ]

            check = cloudstorage_bucket_data_access_audit_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Bucket test-bucket-combined is covered by project "
                f"{GCP_PROJECT_ID} audit logging with DATA_READ and "
                f"DATA_WRITE enabled."
            )
            assert result[0].resource_id == "test-bucket-combined"
            assert result[0].resource_name == "test-bucket-combined"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
