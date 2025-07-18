from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class TestOrganizationsMfaRequired:
    def _create_organization(self, mfa_required=False):
        """Helper method to create an organization with MFA settings"""
        return Organization(
            id=ORG_ID,
            name="Test Organization",
            settings={"multiFactorAuthRequired": mfa_required},
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
                "prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required.organizations_client",
                new=organizations_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.organizations.organizations_mfa_required.organizations_mfa_required import (
                organizations_mfa_required,
            )

            check = organizations_mfa_required()
            return check.execute()

    def test_check_with_mfa_required(self):
        """Test check with MFA required"""
        organization = self._create_organization(mfa_required=True)
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "requires users to set up Multi-Factor Authentication"
            in reports[0].status_extended
        )

    def test_check_with_mfa_not_required(self):
        """Test check with MFA not required"""
        organization = self._create_organization(mfa_required=False)
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert (
            "does not require users to set up Multi-Factor Authentication"
            in reports[0].status_extended
        )

    def test_check_with_no_mfa_setting(self):
        """Test check with no MFA setting"""
        organization = Organization(
            id=ORG_ID,
            name="Test Organization",
            settings={},
        )
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert (
            "does not require users to set up Multi-Factor Authentication"
            in reports[0].status_extended
        )
