from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
    CloudResourceManager,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def mock_api_client(_, __, ___, ____):
    client = MagicMock()

    # Mocking policy
    client.projects().getIamPolicy().execute.return_value = {
        "auditConfigs": [MagicMock()],
        "bindings": [
            {"role": "roles/owner", "members": [MagicMock()]},
            {"role": "roles/viewer", "members": [MagicMock(), MagicMock()]},
        ],
    }

    # Mocking organizations
    client.organizations().search().execute.return_value = {
        "organizations": [
            {"name": "organizations/123456789", "displayName": "Organization 1"},
            {"name": "organizations/987654321", "displayName": "Organization 2"},
        ]
    }

    return client


@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
    new=mock_is_api_active,
)
@patch(
    "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
    new=mock_api_client,
)
class Test_CloudResourceManager_Service:
    def test__get_service__(self):
        api_keys_client = CloudResourceManager(set_mocked_gcp_provider())
        assert api_keys_client.service == "cloudresourcemanager"

    def test__get_project_ids__(self):
        api_keys_client = CloudResourceManager(set_mocked_gcp_provider())
        assert api_keys_client.project_ids.__class__.__name__ == "list"

    def test__get_iam_policy__(self):
        api_keys_client = CloudResourceManager(
            set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        )

        assert len(api_keys_client.projects) == 1
        assert api_keys_client.projects[0].id == GCP_PROJECT_ID
        assert api_keys_client.projects[0].audit_logging

        assert len(api_keys_client.bindings) == 2
        assert api_keys_client.bindings[0].role == "roles/owner"
        assert len(api_keys_client.bindings[0].members) == 1
        assert api_keys_client.bindings[0].project_id == GCP_PROJECT_ID
        assert api_keys_client.bindings[1].role == "roles/viewer"
        assert len(api_keys_client.bindings[1].members) == 2
        assert api_keys_client.bindings[1].project_id == GCP_PROJECT_ID

    def test__get_organizations__(self):
        api_keys_client = CloudResourceManager(
            set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        )

        assert len(api_keys_client.organizations) == 2
        assert api_keys_client.organizations[0].id == "123456789"
        assert api_keys_client.organizations[0].name == "Organization 1"
        assert api_keys_client.organizations[1].id == "987654321"
        assert api_keys_client.organizations[1].name == "Organization 2"
