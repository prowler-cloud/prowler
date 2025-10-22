from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)


class TestCloudStorageBucketLifecycleManagementEnabled:
    def test_bucket_without_lifecycle_rules(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled import (
                cloudstorage_bucket_lifecycle_management_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="no-lifecycle",
                    id="no-lifecycle",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[],
                )
            ]

            check = cloudstorage_bucket_lifecycle_management_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} does not have lifecycle management enabled."
            )
            assert result[0].resource_id == "no-lifecycle"
            assert result[0].resource_name == "no-lifecycle"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_minimal_delete_rule(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled import (
                cloudstorage_bucket_lifecycle_management_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="delete-rule",
                    id="delete-rule",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[
                        {"action": {"type": "Delete"}, "condition": {"age": 30}}
                    ],
                )
            ]

            check = cloudstorage_bucket_lifecycle_management_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} has lifecycle management enabled with 1 valid rule(s)."
            )
            assert result[0].resource_id == "delete-rule"
            assert result[0].resource_name == "delete-rule"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_transition_and_delete_rules(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled import (
                cloudstorage_bucket_lifecycle_management_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="transition-delete",
                    id="transition-delete",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[
                        {
                            "action": {
                                "type": "SetStorageClass",
                                "storageClass": "NEARLINE",
                            },
                            "condition": {"matchesStorageClass": ["STANDARD"]},
                        },
                        {"action": {"type": "Delete"}, "condition": {"age": 365}},
                    ],
                )
            ]

            check = cloudstorage_bucket_lifecycle_management_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} has lifecycle management enabled with 2 valid rule(s)."
            )
            assert result[0].resource_id == "transition-delete"
            assert result[0].resource_name == "transition-delete"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID

    def test_bucket_with_invalid_lifecycle_rules(self):
        cloudstorage_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_client",
                new=cloudstorage_client,
            ),
        ):
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_bucket_lifecycle_management_enabled.cloudstorage_bucket_lifecycle_management_enabled import (
                cloudstorage_bucket_lifecycle_management_enabled,
            )
            from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
                Bucket,
            )

            cloudstorage_client.project_ids = [GCP_PROJECT_ID]
            cloudstorage_client.region = GCP_US_CENTER1_LOCATION

            cloudstorage_client.buckets = [
                Bucket(
                    name="invalid-rules",
                    id="invalid-rules",
                    region=GCP_US_CENTER1_LOCATION,
                    uniform_bucket_level_access=True,
                    public=False,
                    retention_policy=None,
                    project_id=GCP_PROJECT_ID,
                    lifecycle_rules=[
                        {"action": {}, "condition": {"age": 30}},
                        {"action": {"type": "Delete"}, "condition": {}},
                    ],
                )
            ]

            check = cloudstorage_bucket_lifecycle_management_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bucket {cloudstorage_client.buckets[0].name} has lifecycle rules configured but none are valid."
            )
            assert result[0].resource_id == "invalid-rules"
            assert result[0].resource_name == "invalid-rules"
            assert result[0].location == GCP_US_CENTER1_LOCATION
            assert result[0].project_id == GCP_PROJECT_ID
