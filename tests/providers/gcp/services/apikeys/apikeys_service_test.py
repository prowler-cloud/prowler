from unittest.mock import patch

from prowler.providers.gcp.services.apikeys.apikeys_service import APIKeys
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestAPIKeysService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            api_keys_client = APIKeys(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert api_keys_client.service == "apikeys"
            assert api_keys_client.project_ids == [GCP_PROJECT_ID]

            assert len(api_keys_client.keys) == 2

            assert api_keys_client.keys[0].name == "key1"
            assert api_keys_client.keys[0].id.__class__.__name__ == "str"
            assert api_keys_client.keys[0].creation_time == "2021-01-01T00:00:00Z"
            assert api_keys_client.keys[0].restrictions.__class__.__name__ == "dict"
            assert api_keys_client.keys[0].project_id == GCP_PROJECT_ID

            assert api_keys_client.keys[1].name == "key2"
            assert api_keys_client.keys[1].id.__class__.__name__ == "str"
            assert api_keys_client.keys[1].creation_time == "2021-01-01T00:00:00Z"
            assert api_keys_client.keys[1].restrictions.__class__.__name__ == "dict"
            assert api_keys_client.keys[1].project_id == GCP_PROJECT_ID
