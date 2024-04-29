from unittest.mock import patch

from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
    CloudResourceManager,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestCloudResourceManagerService:
    def test_service(self):
        with patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ), patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=mock_api_client,
        ):
            api_keys_client = CloudResourceManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert api_keys_client.service == "cloudresourcemanager"
            assert api_keys_client.project_ids == [GCP_PROJECT_ID]

            assert len(api_keys_client.projects) == 1
            assert api_keys_client.projects[0].id == GCP_PROJECT_ID
            assert api_keys_client.projects[0].audit_logging

            assert len(api_keys_client.bindings) == 2
            assert (
                api_keys_client.bindings[0].role
                == "roles/resourcemanager.organizationAdmin"
            )
            assert len(api_keys_client.bindings[0].members) == 4
            assert api_keys_client.bindings[0].members[0] == "user:mike@example.com"
            assert api_keys_client.bindings[0].members[1] == "group:admins@example.com"
            assert api_keys_client.bindings[0].members[2] == "domain:google.com"
            assert (
                api_keys_client.bindings[0].members[3]
                == "serviceAccount:my-project-id@appspot.gserviceaccount.com"
            )
            assert api_keys_client.bindings[0].project_id == GCP_PROJECT_ID
            assert (
                api_keys_client.bindings[1].role
                == "roles/resourcemanager.organizationViewer"
            )
            assert len(api_keys_client.bindings[1].members) == 1
            assert api_keys_client.bindings[1].members[0] == "user:eve@example.com"
            assert api_keys_client.bindings[1].project_id == GCP_PROJECT_ID

            assert len(api_keys_client.organizations) == 2
            assert api_keys_client.organizations[0].id == "123456789"
            assert api_keys_client.organizations[0].name == "Organization 1"
            assert api_keys_client.organizations[1].id == "987654321"
            assert api_keys_client.organizations[1].name == "Organization 2"
