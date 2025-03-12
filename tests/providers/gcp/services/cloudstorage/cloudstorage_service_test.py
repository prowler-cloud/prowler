from unittest.mock import patch

from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
    CloudStorage,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestCloudStorageService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            cloudstorage_client = CloudStorage(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert cloudstorage_client.service == "storage"
            assert cloudstorage_client.project_ids == [GCP_PROJECT_ID]

            assert len(cloudstorage_client.buckets) == 2
            assert cloudstorage_client.buckets[0].name == "bucket1"
            assert cloudstorage_client.buckets[0].id.__class__.__name__ == "str"
            assert cloudstorage_client.buckets[0].region == "US"
            assert cloudstorage_client.buckets[0].uniform_bucket_level_access
            assert cloudstorage_client.buckets[0].public
            assert cloudstorage_client.buckets[0].retention_policy == {
                "retentionPeriod": 10
            }
            assert cloudstorage_client.buckets[0].project_id == GCP_PROJECT_ID

            assert cloudstorage_client.buckets[1].name == "bucket2"
            assert cloudstorage_client.buckets[1].id.__class__.__name__ == "str"
            assert cloudstorage_client.buckets[1].region == "EU"
            assert not cloudstorage_client.buckets[1].uniform_bucket_level_access
            assert not cloudstorage_client.buckets[1].public
            assert cloudstorage_client.buckets[1].retention_policy is None
            assert cloudstorage_client.buckets[1].project_id == GCP_PROJECT_ID
