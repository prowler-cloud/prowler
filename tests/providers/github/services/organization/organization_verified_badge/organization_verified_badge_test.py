from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_verified_badge:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            assert len(result) == 0

    def test_organization_is_verified_true_pass(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                is_verified=True,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} is verified on GitHub."
            )

    def test_organization_is_verified_false_fail(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                is_verified=False,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} is not verified on GitHub."
            )

    def test_organization_is_verified_none_edge_case(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                is_verified=None,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_verified_badge.organization_verified_badge import (
                organization_verified_badge,
            )

            check = organization_verified_badge()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            # Treat none like not verified (false)
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} is not verified on GitHub."
            )
