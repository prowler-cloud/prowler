from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class TestOrganizationsSecurityContactDefined:
    def _create_organization(self, security_contact=None):
        """Helper method to create an organization with security contact settings"""
        settings = {}
        if security_contact is not None:
            settings["securityContact"] = security_contact

        return Organization(
            id=ORG_ID,
            name="Test Organization",
            settings=settings,
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
                "prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined.organizations_client",
                new=organizations_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.organizations.organizations_security_contact_defined.organizations_security_contact_defined import (
                organizations_security_contact_defined,
            )

            check = organizations_security_contact_defined()
            return check.execute()

    def test_check_with_security_contact_defined(self):
        """Test check with security contact defined"""
        organization = self._create_organization(
            security_contact="security@example.com"
        )
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "has a security contact defined: security@example.com"
            in reports[0].status_extended
        )

    def test_check_with_no_security_contact(self):
        """Test check with no security contact"""
        organization = self._create_organization()
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "does not have a security contact defined" in reports[0].status_extended

    def test_check_with_empty_security_contact(self):
        """Test check with empty security contact"""
        organization = self._create_organization(security_contact="")
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert "does not have a security contact defined" in reports[0].status_extended
