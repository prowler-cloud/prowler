from unittest.mock import MagicMock, patch
from uuid import uuid4

from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
    CloudStorage,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def mock_api_client(_, __, ___, ____):
    client = MagicMock()
    # Mocking buckets

    bucket1_id = str(uuid4())
    bucket2_id = str(uuid4())

    client.buckets().list().execute.return_value = {
        "items": [
            {
                "name": "bucket1",
                "id": bucket1_id,
                "location": "US",
                "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
                "retentionPolicy": {"retentionPeriod": 10},
            },
            {
                "name": "bucket2",
                "id": bucket2_id,
                "location": "EU",
                "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}},
                "retentionPolicy": None,
            },
        ]
    }
    # When getting the bucket IAM policy, the first bucket is public and the second is not
    client.buckets().getIamPolicy().execute.side_effect = [
        {"bindings": "allAuthenticatedUsers"},
        {"bindings": "nobody"},
    ]
    client.buckets().list_next.return_value = None

    return client


@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
    new=mock_is_api_active,
)
@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
    new=mock_api_client,
)
class Test_CloudStorage_Service:
    def test__get_service__(self):
        api_keys_client = CloudStorage(set_mocked_gcp_provider())
        assert api_keys_client.service == "storage"

    def test__get_project_ids__(self):
        api_keys_client = CloudStorage(set_mocked_gcp_provider())
        assert api_keys_client.project_ids.__class__.__name__ == "list"

    def test__get_buckets__(self):
        api_keys_client = CloudStorage(
            set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        )
        assert len(api_keys_client.buckets) == 2
        assert api_keys_client.buckets[0].name == "bucket1"
        assert api_keys_client.buckets[0].id.__class__.__name__ == "str"
        assert api_keys_client.buckets[0].region == "US"
        assert api_keys_client.buckets[0].uniform_bucket_level_access
        assert api_keys_client.buckets[0].public
        assert api_keys_client.buckets[0].retention_policy == {"retentionPeriod": 10}
        assert api_keys_client.buckets[0].project_id == GCP_PROJECT_ID

        assert api_keys_client.buckets[1].name == "bucket2"
        assert api_keys_client.buckets[1].id.__class__.__name__ == "str"
        assert api_keys_client.buckets[1].region == "EU"
        assert not api_keys_client.buckets[1].uniform_bucket_level_access
        assert not api_keys_client.buckets[1].public
        assert api_keys_client.buckets[1].retention_policy is None
        assert api_keys_client.buckets[1].project_id == GCP_PROJECT_ID
