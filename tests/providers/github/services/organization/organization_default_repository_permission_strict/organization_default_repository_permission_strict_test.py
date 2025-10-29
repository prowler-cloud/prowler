from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_default_repository_permission_strict:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict import (
                organization_default_repository_permission_strict,
            )

            check = organization_default_repository_permission_strict()
            result = check.execute()
            assert len(result) == 0

    def test_permission_read(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                base_permission="read",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict import (
                organization_default_repository_permission_strict,
            )

            check = organization_default_repository_permission_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} base repository permission is 'read', which is strict."
            )

    def test_permission_none(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                base_permission="none",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict import (
                organization_default_repository_permission_strict,
            )

            check = organization_default_repository_permission_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} base repository permission is 'none', which is strict."
            )

    def test_permission_write(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                base_permission="write",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict import (
                organization_default_repository_permission_strict,
            )

            check = organization_default_repository_permission_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} base repository permission is 'write', which is not strict."
            )

    def test_permission_admin(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                base_permission="admin",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict import (
                organization_default_repository_permission_strict,
            )

            check = organization_default_repository_permission_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} base repository permission is 'admin', which is not strict."
            )

    def test_permission_unknown_none_skipped(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                base_permission=None,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_repository_permission_strict.organization_default_repository_permission_strict import (
                organization_default_repository_permission_strict,
            )

            check = organization_default_repository_permission_strict()
            result = check.execute()
            assert len(result) == 0
