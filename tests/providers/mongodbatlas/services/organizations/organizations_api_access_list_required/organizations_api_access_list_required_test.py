from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class TestOrganizationsApiAccessListRequired:
    def _create_organization(self, api_access_list_required=False):
        """Helper method to create an organization with API access list settings"""
        return Organization(
            id=ORG_ID,
            name="Test Organization",
            settings={"apiAccessListRequired": api_access_list_required},
        )

    def _execute_check_with_organization(self, organization):
        """Helper method to execute check with an organization"""
        organizations_client = MagicMock()
        organizations_client.organizations = {ORG_ID: organization}

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_mongodbatlas_provider(),
            ),
            patch(
                "prowler.providers.mongodbatlas.services.organizations.organizations_api_access_list_required.organizations_api_access_list_required.organizations_client",
                new=organizations_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.organizations.organizations_api_access_list_required.organizations_api_access_list_required import (
                organizations_api_access_list_required,
            )

            check = organizations_api_access_list_required()
            return check.execute()

    def test_check_with_api_access_list_required(self):
        """Test check with API access list required"""
        organization = self._create_organization(api_access_list_required=True)
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "requires API operations to originate from an IP Address added to the API access list"
            in reports[0].status_extended
        )

    def test_check_with_api_access_list_not_required(self):
        """Test check with API access list not required"""
        organization = self._create_organization(api_access_list_required=False)
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert (
            "does not require API operations to originate from an IP Address added to the API access list"
            in reports[0].status_extended
        )

    def test_check_with_no_api_access_list_setting(self):
        """Test check with no API access list setting"""
        organization = Organization(
            id=ORG_ID,
            name="Test Organization",
            settings={},
        )
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert (
            "does not require API operations to originate from an IP Address added to the API access list"
            in reports[0].status_extended
        )
