from unittest.mock import MagicMock, patch

from github import GithubException, RateLimitExceededException

from prowler.providers.github.services.organization.organization_service import (
    Org,
    Organization,
)
from tests.providers.github.github_fixtures import set_mocked_github_provider


def mock_list_organizations(_):
    return {
        1: Org(
            id=1,
            name="test-organization",
            mfa_required=True,
        ),
    }


@patch(
    "prowler.providers.github.services.organization.organization_service.Organization._list_organizations",
    new=mock_list_organizations,
)
class Test_Repository_Service:
    def test_get_client(self):
        repository_service = Organization(set_mocked_github_provider())
        assert repository_service.clients[0].__class__.__name__ == "Github"

    def test_get_service(self):
        repository_service = Organization(set_mocked_github_provider())
        assert repository_service.__class__.__name__ == "Organization"

    def test_list_organizations(self):
        repository_service = Organization(set_mocked_github_provider())
        assert len(repository_service.organizations) == 1
        assert repository_service.organizations[1].name == "test-organization"
        assert repository_service.organizations[1].mfa_required


class Test_Organization_Scoping:
    def setup_method(self):
        self.mock_org1 = MagicMock()
        self.mock_org1.id = 1
        self.mock_org1.login = "test-org1"
        self.mock_org1.two_factor_requirement_enabled = True

        self.mock_org2 = MagicMock()
        self.mock_org2.id = 2
        self.mock_org2.login = "test-org2"
        self.mock_org2.two_factor_requirement_enabled = False

        self.mock_user = MagicMock()
        self.mock_user.id = 100
        self.mock_user.login = "test-user"

    def test_no_organization_scoping(self):
        """Test that all user organizations are returned when no scoping is specified"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = []

        mock_client = MagicMock()
        mock_user = MagicMock()
        mock_orgs = MagicMock()
        mock_orgs.totalCount = 2
        mock_orgs.__iter__ = MagicMock(
            return_value=iter([self.mock_org1, self.mock_org2])
        )
        mock_user.get_orgs.return_value = mock_orgs
        mock_client.get_user.return_value = mock_user

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            assert len(orgs) == 2
            assert 1 in orgs
            assert 2 in orgs
            assert orgs[1].name == "test-org1"
            assert orgs[2].name == "test-org2"

    def test_specific_organization_scoping(self):
        """Test that only specified organizations are returned"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["test-org1"]

        mock_client = MagicMock()
        mock_client.get_organization.return_value = self.mock_org1

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            assert len(orgs) == 1
            assert 1 in orgs
            assert orgs[1].name == "test-org1"
            assert orgs[1].mfa_required is True
            mock_client.get_organization.assert_called_once_with("test-org1")

    def test_multiple_organization_scoping(self):
        """Test that multiple specified organizations are returned"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["test-org1", "test-org2"]

        mock_client = MagicMock()
        mock_client.get_organization.side_effect = [self.mock_org1, self.mock_org2]

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            assert len(orgs) == 2
            assert 1 in orgs
            assert 2 in orgs
            assert orgs[1].name == "test-org1"
            assert orgs[2].name == "test-org2"
            assert mock_client.get_organization.call_count == 2

    def test_organization_as_user_fallback(self):
        """Test that organization scoping falls back to user when organization not found"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["test-user"]

        mock_client = MagicMock()
        # Organization lookup fails
        mock_client.get_organization.side_effect = GithubException(
            404, "Not Found", None
        )
        # User lookup succeeds
        mock_client.get_user.return_value = self.mock_user

        # Create service without calling the parent constructor
        organization_service = Organization.__new__(Organization)
        organization_service.clients = [mock_client]
        organization_service.provider = provider

        orgs = organization_service._list_organizations()

        assert len(orgs) == 1
        assert 100 in orgs
        assert orgs[100].name == "test-user"
        assert orgs[100].mfa_required is None  # Users don't have MFA requirements
        mock_client.get_organization.assert_called_once_with("test-user")
        mock_client.get_user.assert_called_once_with("test-user")

    def test_repository_only_scoping_no_organization_checks(self):
        """Test that repository-only scoping does NOT perform organization checks"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner1/repo1", "owner2/repo2"]
        provider.organizations = []

        mock_client = MagicMock()

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            # Should be empty - no organization checks when only repositories are specified
            assert len(orgs) == 0
            # Should not call get_organization at all
            mock_client.get_organization.assert_not_called()
            mock_client.get_user.assert_not_called()

    def test_combined_repository_and_organization_scoping(self):
        """Test that both repository owners and specified organizations are included"""
        provider = set_mocked_github_provider()
        provider.repositories = ["owner1/repo1"]
        provider.organizations = ["specific-org"]

        mock_client = MagicMock()
        # Mock different organizations for owner1 and specific-org
        mock_owner_org = MagicMock()
        mock_owner_org.id = 1
        mock_owner_org.login = "owner1"
        mock_owner_org.two_factor_requirement_enabled = True

        mock_specific_org = MagicMock()
        mock_specific_org.id = 2
        mock_specific_org.login = "specific-org"
        mock_specific_org.two_factor_requirement_enabled = False

        mock_client.get_organization.side_effect = [
            mock_owner_org,
            mock_specific_org,
        ]

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            assert len(orgs) == 2
            assert 1 in orgs
            assert 2 in orgs
            assert orgs[1].name == "owner1"
            assert orgs[2].name == "specific-org"
            assert mock_client.get_organization.call_count == 2

    def test_organization_not_found(self):
        """Test that inaccessible organizations are skipped with warning"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["nonexistent-org"]

        mock_client = MagicMock()
        # Both organization and user lookups fail
        mock_client.get_organization.side_effect = Exception("404 Not Found")
        mock_client.get_user.side_effect = Exception("404 Not Found")

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            # Should be empty since organization/user wasn't found
            assert len(orgs) == 0

    def test_organization_error_handling(self):
        """Test that other errors (non-404) are handled gracefully"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["error-org"]

        mock_client = MagicMock()
        # Organization lookup fails with non-404 error
        mock_client.get_organization.side_effect = Exception(
            "500 Internal Server Error"
        )

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            # Should be empty since organization wasn't accessible
            assert len(orgs) == 0

    def test_duplicate_organizations_handling(self):
        """Test that duplicate organizations (e.g., from repositories and organizations) are handled correctly"""
        provider = set_mocked_github_provider()
        provider.repositories = ["test-org1/repo1"]
        provider.organizations = ["test-org1"]  # Same organization specified twice

        mock_client = MagicMock()
        mock_client.get_organization.return_value = self.mock_org1

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            orgs = organization_service._list_organizations()

            # Should only have one organization despite being specified twice
            assert len(orgs) == 1
            assert 1 in orgs
            assert orgs[1].name == "test-org1"
            # Should only call get_organization once due to set deduplication
            mock_client.get_organization.assert_called_once_with("test-org1")


class Test_Organization_ErrorHandling:
    def setup_method(self):
        self.mock_org1 = MagicMock()
        self.mock_org1.id = 1
        self.mock_org1.login = "test-org1"
        self.mock_org1.two_factor_requirement_enabled = True

    def test_github_api_error_handling(self):
        """Test that GitHub API errors are handled properly"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["test-org1"]

        mock_client = MagicMock()
        mock_client.get_organization.side_effect = GithubException(
            403, "Forbidden", None
        )

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            with patch(
                "prowler.providers.github.services.organization.organization_service.logger"
            ) as mock_logger:
                orgs = organization_service._list_organizations()

                # Should be empty due to API error
                assert len(orgs) == 0
                # Should log specific error message
                mock_logger.warning.assert_called()
                # Check if Access denied message was logged (could be in warning or error calls)
                log_messages = [
                    str(call)
                    for call in mock_logger.warning.call_args_list
                    + mock_logger.error.call_args_list
                ]
                assert any("Access denied" in msg for msg in log_messages)

    def test_rate_limit_error_handling(self):
        """Test that rate limit errors are logged appropriately"""
        provider = set_mocked_github_provider()
        provider.repositories = []
        provider.organizations = ["test-org1"]

        mock_client = MagicMock()
        mock_client.get_organization.side_effect = RateLimitExceededException(
            429, "Rate limit exceeded", None
        )

        with patch(
            "prowler.providers.github.services.organization.organization_service.GithubService.__init__"
        ):
            organization_service = Organization(provider)
            organization_service.clients = [mock_client]
            organization_service.provider = provider

            with patch(
                "prowler.providers.github.services.organization.organization_service.logger"
            ) as mock_logger:
                # Rate limit errors should be caught and logged at the outer level
                orgs = organization_service._list_organizations()

                # Should be empty due to rate limit error
                assert len(orgs) == 0
                # Should log rate limit error
                mock_logger.error.assert_called()
                assert "Rate limit exceeded" in str(mock_logger.error.call_args)
