from unittest.mock import MagicMock, patch

from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organization,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    set_mocked_mongodbatlas_provider,
)


class TestOrganizationsServiceAccountSecretsExpiration:
    def _create_organization(self, max_validity_hours=None):
        """Helper method to create an organization with service account secrets expiration settings"""
        settings = {}
        if max_validity_hours is not None:
            settings["maxServiceAccountSecretValidityInHours"] = max_validity_hours

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
                "prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration.organizations_client",
                new=organizations_client,
            ),
        ):
            from prowler.providers.mongodbatlas.services.organizations.organizations_service_account_secrets_expiration.organizations_service_account_secrets_expiration import (
                organizations_service_account_secrets_expiration,
            )

            check = organizations_service_account_secrets_expiration()
            return check.execute()

    def test_check_with_valid_expiration_hours(self):
        """Test check with valid expiration hours (8 hours)"""
        organization = self._create_organization(max_validity_hours=8)
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "within the recommended threshold of 8 hours" in reports[0].status_extended
        )

    def test_check_with_valid_expiration_hours_lower(self):
        """Test check with valid expiration hours (4 hours)"""
        organization = self._create_organization(max_validity_hours=4)
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "PASS"
        assert (
            "within the recommended threshold of 8 hours" in reports[0].status_extended
        )

    def test_check_with_invalid_expiration_hours(self):
        """Test check with invalid expiration hours (24 hours)"""
        organization = self._create_organization(max_validity_hours=24)
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert (
            "exceeds the recommended threshold of 8 hours" in reports[0].status_extended
        )

    def test_check_with_no_expiration_setting(self):
        """Test check with no expiration setting"""
        organization = self._create_organization()
        reports = self._execute_check_with_organization(organization)

        assert len(reports) == 1
        assert reports[0].status == "FAIL"
        assert (
            "does not have a maximum period expiration configured"
            in reports[0].status_extended
        )
