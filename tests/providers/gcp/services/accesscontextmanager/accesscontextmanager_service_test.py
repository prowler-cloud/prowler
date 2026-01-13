from unittest.mock import MagicMock, patch

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_api_client,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


class TestAccessContextManagerService:
    def test_service(self):
        # Mock cloudresourcemanager_client before importing accesscontextmanager
        mock_crm_client = MagicMock()
        mock_crm_client.organizations = [
            MagicMock(id="123456789", name="Organization 1"),
        ]

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
            patch(
                "prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service.cloudresourcemanager_client",
                new=mock_crm_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                AccessContextManager,
            )

            accesscontextmanager_client = AccessContextManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert accesscontextmanager_client.service == "accesscontextmanager"
            assert accesscontextmanager_client.project_ids == [GCP_PROJECT_ID]

            # Should have 2 service perimeters from the first access policy
            assert len(accesscontextmanager_client.service_perimeters) == 2

            # First service perimeter
            assert (
                accesscontextmanager_client.service_perimeters[0].name
                == "accessPolicies/123456/servicePerimeters/perimeter1"
            )
            assert (
                accesscontextmanager_client.service_perimeters[0].title
                == "Test Perimeter 1"
            )
            assert (
                accesscontextmanager_client.service_perimeters[0].perimeter_type
                == "PERIMETER_TYPE_REGULAR"
            )
            assert accesscontextmanager_client.service_perimeters[0].resources == [
                f"projects/{GCP_PROJECT_ID}"
            ]
            assert accesscontextmanager_client.service_perimeters[
                0
            ].restricted_services == [
                "storage.googleapis.com",
                "bigquery.googleapis.com",
            ]
            assert (
                accesscontextmanager_client.service_perimeters[0].policy_name
                == "accessPolicies/123456"
            )

            # Second service perimeter
            assert (
                accesscontextmanager_client.service_perimeters[1].name
                == "accessPolicies/123456/servicePerimeters/perimeter2"
            )
            assert (
                accesscontextmanager_client.service_perimeters[1].title
                == "Test Perimeter 2"
            )
            assert (
                accesscontextmanager_client.service_perimeters[1].perimeter_type
                == "PERIMETER_TYPE_BRIDGE"
            )
            assert accesscontextmanager_client.service_perimeters[1].resources == []
            assert accesscontextmanager_client.service_perimeters[
                1
            ].restricted_services == [
                "compute.googleapis.com",
            ]
            assert (
                accesscontextmanager_client.service_perimeters[1].policy_name
                == "accessPolicies/123456"
            )

    def test_get_service_perimeters_access_policies_error(self):
        """Test error handling when listing access policies fails."""
        mock_crm_client = MagicMock()
        mock_crm_client.organizations = [
            MagicMock(id="123456789", name="Organization 1"),
        ]

        mock_client = MagicMock()

        def mock_list_access_policies_error(parent):
            return_value = MagicMock()
            return_value.execute.side_effect = Exception("Access denied")
            return return_value

        mock_client.accessPolicies().list = mock_list_access_policies_error

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                return_value=mock_client,
            ),
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service.cloudresourcemanager_client",
                new=mock_crm_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                AccessContextManager,
            )

            accesscontextmanager_client = AccessContextManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert len(accesscontextmanager_client.service_perimeters) == 0

    def test_get_service_perimeters_list_perimeters_error(self):
        """Test error handling when listing service perimeters fails."""
        mock_crm_client = MagicMock()
        mock_crm_client.organizations = [
            MagicMock(id="123456789", name="Organization 1"),
        ]

        mock_client = MagicMock()

        def mock_list_access_policies(parent):
            return_value = MagicMock()
            return_value.execute.return_value = {
                "accessPolicies": [{"name": "accessPolicies/123456"}]
            }
            return return_value

        def mock_list_perimeters_error(parent):
            return_value = MagicMock()
            return_value.execute.side_effect = Exception("Permission denied")
            return return_value

        mock_client.accessPolicies().list = mock_list_access_policies
        mock_client.accessPolicies().list_next.return_value = None
        mock_client.accessPolicies().servicePerimeters().list = (
            mock_list_perimeters_error
        )

        with (
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                return_value=mock_client,
            ),
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            patch(
                "prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service.cloudresourcemanager_client",
                new=mock_crm_client,
            ),
        ):
            from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
                AccessContextManager,
            )

            accesscontextmanager_client = AccessContextManager(
                set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID])
            )
            assert len(accesscontextmanager_client.service_perimeters) == 0
