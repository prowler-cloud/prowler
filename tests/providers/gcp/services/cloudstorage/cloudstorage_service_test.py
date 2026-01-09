from unittest.mock import MagicMock, patch

from googleapiclient.errors import HttpError

from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
    CloudStorage,
    RetentionPolicy,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestCloudStorageService:
    def test_service(self):
        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=mock_api_client,
            ),
        ):
            cloudstorage_client = CloudStorage(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert cloudstorage_client.service == "storage"
            assert cloudstorage_client.project_ids == [GCP_PROJECT_ID]

            assert len(cloudstorage_client.buckets) == 2
            assert cloudstorage_client.buckets[0].name == "bucket1"
            assert cloudstorage_client.buckets[0].id.__class__.__name__ == "str"
            assert cloudstorage_client.buckets[0].region == "us"
            assert cloudstorage_client.buckets[0].uniform_bucket_level_access
            assert cloudstorage_client.buckets[0].public

            assert isinstance(
                cloudstorage_client.buckets[0].retention_policy, RetentionPolicy
            )
            assert (
                cloudstorage_client.buckets[0].retention_policy.retention_period == 10
            )
            assert cloudstorage_client.buckets[0].retention_policy.is_locked is False
            assert (
                cloudstorage_client.buckets[0].retention_policy.effective_time is None
            )
            assert cloudstorage_client.buckets[0].project_id == GCP_PROJECT_ID

            assert cloudstorage_client.buckets[1].name == "bucket2"
            assert cloudstorage_client.buckets[1].id.__class__.__name__ == "str"
            assert cloudstorage_client.buckets[1].region == "eu"
            assert not cloudstorage_client.buckets[1].uniform_bucket_level_access
            assert not cloudstorage_client.buckets[1].public
            assert cloudstorage_client.buckets[1].retention_policy is None
            assert cloudstorage_client.buckets[1].project_id == GCP_PROJECT_ID

    def test_vpc_service_controls_blocked(self):
        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            ) as mock_client,
        ):
            mock_resp = MagicMock()
            mock_resp.status = 403
            mock_resp.reason = "Forbidden"

            vpc_error = HttpError(
                resp=mock_resp,
                content=b'{"error": {"message": "Request is prohibited by organization\'s policy. vpcServiceControlsUniqueIdentifier: 12345"}}',
            )

            mock_buckets = MagicMock()
            mock_buckets.list.return_value.execute.side_effect = vpc_error
            mock_client.return_value.buckets.return_value = mock_buckets

            cloudstorage_client = CloudStorage(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert (
                GCP_PROJECT_ID
                in cloudstorage_client.vpc_service_controls_protected_projects
            )
            assert len(cloudstorage_client.buckets) == 0
