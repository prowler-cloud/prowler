from datetime import datetime
from unittest.mock import MagicMock, patch

from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
    CloudResourceManager,
)
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestIAMService:
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import IAM

            iam_client = IAM(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))
            assert iam_client.service == "iam"
            assert iam_client.project_ids == [GCP_PROJECT_ID]

            assert len(iam_client.service_accounts) == 2
            assert (
                iam_client.service_accounts[0].name
                == f"projects/{GCP_PROJECT_ID}/serviceAccounts/service-account1@{GCP_PROJECT_ID}.iam.gserviceaccount.com"
            )
            assert iam_client.service_accounts[0].email == "service-account1@gmail.com"
            assert iam_client.service_accounts[0].display_name == "Service Account 1"
            assert iam_client.service_accounts[0].uniqueId == "111222233334444"
            assert len(iam_client.service_accounts[0].keys) == 2
            assert iam_client.service_accounts[0].keys[0].name == "key1"
            assert iam_client.service_accounts[0].keys[0].valid_after == datetime(
                2021, 1, 1, 0, 0, 0
            )
            assert iam_client.service_accounts[0].keys[0].valid_before == datetime(
                2022, 1, 1, 0, 0, 0
            )
            assert iam_client.service_accounts[0].keys[0].origin == "GOOGLE_PROVIDED"
            assert iam_client.service_accounts[0].keys[0].type == "SYSTEM_MANAGED"
            assert iam_client.service_accounts[0].keys[1].name == "key2"
            assert iam_client.service_accounts[0].keys[1].valid_after == datetime(
                2021, 1, 1, 0, 0, 0
            )
            assert iam_client.service_accounts[0].keys[1].valid_before == datetime(
                2022, 1, 1, 0, 0, 0
            )
            assert iam_client.service_accounts[0].keys[1].origin == "ORIGIN_UNSPECIFIED"
            assert iam_client.service_accounts[0].keys[1].type == "USER_MANAGED"
            assert (
                iam_client.service_accounts[1].name
                == f"projects/{GCP_PROJECT_ID}/serviceAccounts/service-account2@{GCP_PROJECT_ID}.iam.gserviceaccount.com"
            )
            assert iam_client.service_accounts[1].email == "service-account2@gmail.com"
            assert iam_client.service_accounts[1].display_name == "Service Account 2"
            assert iam_client.service_accounts[1].uniqueId == "55566666777888999"
            assert len(iam_client.service_accounts[1].keys) == 1
            assert iam_client.service_accounts[1].keys[0].name == "key3"
            assert iam_client.service_accounts[1].keys[0].valid_after == datetime(
                2021, 1, 1, 0, 0, 0
            )
            assert iam_client.service_accounts[1].keys[0].valid_before == datetime(
                2022, 1, 1, 0, 0, 0
            )
            assert iam_client.service_accounts[1].keys[0].origin == "USER_PROVIDED"
            assert iam_client.service_accounts[1].keys[0].type == "KEY_TYPE_UNSPECIFIED"


class TestAccessApproval:
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import AccessApproval

            access_approval_client = AccessApproval(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert access_approval_client.service == "accessapproval"
            assert access_approval_client.project_ids == [GCP_PROJECT_ID]

            assert (
                access_approval_client.settings[GCP_PROJECT_ID].name
                == "projects/123/accessApprovalSettings"
            )
            assert (
                access_approval_client.settings[GCP_PROJECT_ID].project_id
                == GCP_PROJECT_ID
            )
            assert access_approval_client.settings_lookup_failed == set()

    def _build_with_http_error(self, status):
        from googleapiclient.errors import HttpError

        http_error = HttpError(
            resp=MagicMock(status=status, reason="error"),
            content=b'{"error": {"code": %d, "message": "error"}}' % status,
            uri="https://accessapproval.googleapis.com/v1/projects/123/accessApprovalSettings",
        )
        client = MagicMock()
        client.projects().getAccessApprovalSettings().execute.side_effect = http_error

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                return_value=client,
            ),
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import AccessApproval

            return AccessApproval(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

    def test_settings_not_found_means_not_enabled(self):
        """A 404 means Access Approval is not enabled: no settings, no error."""
        access_approval_client = self._build_with_http_error(404)

        assert access_approval_client.settings == {}
        assert access_approval_client.settings_lookup_failed == set()

    def test_settings_permission_denied_is_tracked(self):
        """A 403 (or API disabled) is a lookup failure, not 'not enabled'."""
        access_approval_client = self._build_with_http_error(403)

        assert access_approval_client.settings == {}
        assert access_approval_client.settings_lookup_failed == {GCP_PROJECT_ID}


class TestEssentialContacts:
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
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(  # Reinstancing the CloudResourceManager client to secure that is not instancied first by a test
                "prowler.providers.gcp.services.iam.iam_service.cloudresourcemanager_client",
                new=CloudResourceManager(
                    set_mocked_gcp_provider(),
                ),
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import EssentialContacts

            essential_contacts_client = EssentialContacts(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )

            assert essential_contacts_client.service == "essentialcontacts"
            assert essential_contacts_client.project_ids == [GCP_PROJECT_ID]

            assert len(essential_contacts_client.organizations) == 2

            assert essential_contacts_client.organizations[0].name == "Organization 1"
            assert essential_contacts_client.organizations[0].id == "123456789"
            assert essential_contacts_client.organizations[0].contacts

            assert essential_contacts_client.organizations[1].name == "Organization 2"
            assert essential_contacts_client.organizations[1].id == "987654321"
            assert not essential_contacts_client.organizations[1].contacts

    def test_api_disabled_project_is_tracked_as_inactive(self):
        """A DISABLED serviceusage state must land in inactive_api_project_ids."""
        serviceusage_client = MagicMock()
        serviceusage_client.services().get().execute.return_value = {
            "state": "DISABLED"
        }

        provider = set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
        # The fixture is a MagicMock: make the API-activation precheck run.
        provider.skip_api_check = False

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.discovery.build",
                return_value=serviceusage_client,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                return_value=MagicMock(),
            ),
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=provider,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import AccessApproval

            access_approval_client = AccessApproval(provider)

            assert access_approval_client.project_ids == []
            assert access_approval_client.api_disabled_project_ids == {GCP_PROJECT_ID}
            assert access_approval_client.api_state_unknown_project_ids == set()
            assert access_approval_client.settings == {}
