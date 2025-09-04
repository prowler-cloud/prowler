from unittest.mock import patch

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
    Organizations,
    OrganizationSettings,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


def mock_organizations_list_organizations(_):
    return {
        ORG_ID: Organization(
            id=ORG_ID,
            name="Test Organization",
            settings=OrganizationSettings(
                api_access_list_required=True,
                ip_access_list_enabled=True,
                ip_access_list=["192.168.1.0/24"],
                multi_factor_auth_required=True,
                security_contact="security@example.com",
                max_service_account_secret_validity_in_hours=8,
            ),
            location="global",
        )
    }


@patch(
    "prowler.providers.mongodbatlas.services.organizations.organizations_service.Organizations._list_organizations",
    new=mock_organizations_list_organizations,
)
class Test_Organizations_Service:
    def test_get_client(self):
        organizations_service_client = Organizations(set_mocked_mongodbatlas_provider())
        assert organizations_service_client.__class__.__name__ == "Organizations"

    def test_list_organizations(self):
        organizations_service_client = Organizations(set_mocked_mongodbatlas_provider())
        assert len(organizations_service_client.organizations) == 1

        organization = organizations_service_client.organizations[ORG_ID]

        assert organization.id == ORG_ID
        assert organization.name == "Test Organization"
        assert organization.location == "global"
        assert organization.settings is not None
        assert organization.settings.api_access_list_required is True
        assert organization.settings.ip_access_list_enabled is True
        assert organization.settings.ip_access_list == ["192.168.1.0/24"]
        assert organization.settings.multi_factor_auth_required is True
        assert organization.settings.security_contact == "security@example.com"
        assert organization.settings.max_service_account_secret_validity_in_hours == 8


class Test_Organizations_Service_Integration:
    def setup_method(self):
        self.mock_provider = set_mocked_mongodbatlas_provider()

    def test_list_organizations_with_real_api_calls(self):
        """Test organizations listing with mocked API responses"""
        with patch.object(Organizations, "__init__", lambda x, y: None):
            organizations_service = Organizations(self.mock_provider)
            organizations_service.provider = self.mock_provider

            # Mock _paginate_request to return organization data
            mock_org_data = [{"id": ORG_ID, "name": "Test Organization"}]
            with patch.object(
                organizations_service, "_paginate_request", return_value=mock_org_data
            ):
                # Mock _make_request to return settings data
                mock_settings = {
                    "apiAccessListRequired": True,
                    "ipAccessListEnabled": True,
                    "ipAccessList": ["192.168.1.0/24"],
                    "multiFactorAuthRequired": True,
                    "securityContact": "security@example.com",
                    "maxServiceAccountSecretValidityInHours": 8,
                }
                with patch.object(
                    organizations_service, "_make_request", return_value=mock_settings
                ):
                    organizations = organizations_service._list_organizations()

                    assert len(organizations) == 1
                    assert ORG_ID in organizations

                    organization = organizations[ORG_ID]
                    assert organization.name == "Test Organization"
                    assert organization.settings is not None
                    assert organization.settings.api_access_list_required is True

    def test_list_organizations_api_error_handling(self):
        """Test that API errors are handled gracefully"""
        with patch.object(Organizations, "__init__", lambda x, y: None):
            organizations_service = Organizations(self.mock_provider)
            organizations_service.provider = self.mock_provider

            # Mock _paginate_request to raise an exception
            with patch.object(
                organizations_service,
                "_paginate_request",
                side_effect=Exception("API Error"),
            ):
                with patch(
                    "prowler.providers.mongodbatlas.services.organizations.organizations_service.logger"
                ) as mock_logger:
                    organizations = organizations_service._list_organizations()

                    # Should be empty due to API error
                    assert len(organizations) == 0
                    # Should log error
                    mock_logger.error.assert_called()

    def test_organization_settings_error_handling(self):
        """Test that organization settings errors are handled gracefully"""
        with patch.object(Organizations, "__init__", lambda x, y: None):
            organizations_service = Organizations(self.mock_provider)
            organizations_service.provider = self.mock_provider

            # Mock _paginate_request to return organization data
            mock_org_data = [{"id": ORG_ID, "name": "Test Organization"}]
            with patch.object(
                organizations_service, "_paginate_request", return_value=mock_org_data
            ):
                # Mock _make_request to raise an exception for settings
                with patch.object(
                    organizations_service,
                    "_make_request",
                    side_effect=Exception("Settings API Error"),
                ):
                    with patch(
                        "prowler.providers.mongodbatlas.services.organizations.organizations_service.logger"
                    ) as mock_logger:
                        organizations = organizations_service._list_organizations()

                        # Should still create organization but with None settings
                        assert len(organizations) == 1
                        assert ORG_ID in organizations

                        organization = organizations[ORG_ID]
                        assert organization.name == "Test Organization"
                        assert organization.settings is None
                        # Should log error for settings
                        mock_logger.error.assert_called()


class Test_Organization_Model:
    def test_organization_model_creation(self):
        """Test Organization model creation with all fields"""
        settings = OrganizationSettings(
            api_access_list_required=True,
            ip_access_list_enabled=True,
            ip_access_list=["192.168.1.0/24"],
            multi_factor_auth_required=True,
            security_contact="security@example.com",
            max_service_account_secret_validity_in_hours=8,
        )

        organization = Organization(
            id=ORG_ID,
            name="Test Organization",
            settings=settings,
            location="global",
        )

        assert organization.id == ORG_ID
        assert organization.name == "Test Organization"
        assert organization.location == "global"
        assert organization.settings == settings

    def test_organization_settings_model_creation(self):
        """Test OrganizationSettings model creation with all fields"""
        settings = OrganizationSettings(
            api_access_list_required=True,
            ip_access_list_enabled=True,
            ip_access_list=["192.168.1.0/24", "10.0.0.0/8"],
            multi_factor_auth_required=True,
            security_contact="security@example.com",
            max_service_account_secret_validity_in_hours=24,
        )

        assert settings.api_access_list_required is True
        assert settings.ip_access_list_enabled is True
        assert settings.ip_access_list == ["192.168.1.0/24", "10.0.0.0/8"]
        assert settings.multi_factor_auth_required is True
        assert settings.security_contact == "security@example.com"
        assert settings.max_service_account_secret_validity_in_hours == 24
