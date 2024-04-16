from unittest.mock import MagicMock, patch
from uuid import uuid4

from prowler.providers.gcp.services.apikeys.apikeys_service import APIKeys
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def mock_api_client(_, __, ___, ____):
    client = MagicMock()
    client.projects().locations().keys().list().execute.return_value = {
        "keys": [
            {
                "displayName": "key1",
                "uid": str(uuid4()),
                "createTime": "2021-01-01T00:00:00Z",
                "restrictions": {},
            },
            {
                "displayName": "key2",
                "uid": str(uuid4()),
                "createTime": "2021-01-01T00:00:00Z",
                "restrictions": {},
            },
        ]
    }
    # Next page is None to not enter in the while infinite loop
    client.projects().locations().keys().list_next.return_value = None

    return client


@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
    new=mock_is_api_active,
)
@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
    new=mock_api_client,
)
class Test_APIKeys_Service:
    def test__get_service__(self):
        api_keys_client = APIKeys(set_mocked_gcp_provider())
        assert api_keys_client.service == "apikeys"

    def test__get_project_ids__(self):
        api_keys_client = APIKeys(set_mocked_gcp_provider())
        assert api_keys_client.project_ids.__class__.__name__ == "list"

    def test__get_keys__(self):
        api_keys_client = APIKeys(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

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
