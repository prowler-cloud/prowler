from unittest.mock import patch

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
