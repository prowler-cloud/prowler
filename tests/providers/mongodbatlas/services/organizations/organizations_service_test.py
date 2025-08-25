from unittest.mock import patch

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class TestOrganizationsService:
    def test_organizations_service_initialization(self):
        """Test Organizations service initialization"""
        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_mongodbatlas_provider(),
        ):
            with patch.object(
                Organizations, "_list_organizations", return_value={}
            ) as mock_list:
                service = Organizations(set_mocked_mongodbatlas_provider())
                assert service.organizations == {}
                mock_list.assert_called_once()

    def test_process_organization(self):
        """Test organization processing"""
        provider = set_mocked_mongodbatlas_provider()

        with patch.object(Organizations, "_list_organizations", return_value={}):
            service = Organizations(provider)

            # Mock the settings request
            mock_settings = {
                "apiAccessListRequired": True,
                "multiFactorAuthRequired": True,
                "maxServiceAccountSecretValidityInHours": 8,
                "securityContact": "security@example.com",
            }

            with patch.object(
                service, "_get_organization_settings", return_value=mock_settings
            ):
                org_data = {"id": ORG_ID, "name": "Test Organization"}

                organization = service._process_organization(org_data)

                assert organization.id == ORG_ID
                assert organization.name == "Test Organization"
                assert organization.settings == mock_settings

    def test_get_organization_settings_error_handling(self):
        """Test error handling in get organization settings"""
        provider = set_mocked_mongodbatlas_provider()

        with patch.object(Organizations, "_list_organizations", return_value={}):
            service = Organizations(provider)

            # Mock the request to raise an exception
            with patch.object(
                service, "_make_request", side_effect=Exception("API Error")
            ):
                settings = service._get_organization_settings(ORG_ID)
                assert settings == {}
