from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_repository_creation_limited:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 0

    def test_repository_creation_disabled_globally(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_repositories=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has disabled repository creation for members."
            )

    def test_repository_creation_allowed_for_members(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_repositories=True,
                members_can_create_public_repositories=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "public repositories" in result[0].status_extended
            assert "repositories of any type" in result[0].status_extended

    def test_repository_creation_disabled_per_visibility(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_can_create_public_repositories=False,
                members_can_create_private_repositories=False,
                members_can_create_internal_repositories=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has disabled repository creation for members."
            )

    def test_repository_creation_disabled_via_members_allowed_type(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=None,
                members_allowed_repository_creation_type="none",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_repository_creation_limited.organization_repository_creation_limited import (
                organization_repository_creation_limited,
            )

            check = organization_repository_creation_limited()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has disabled repository creation for members."
            )
