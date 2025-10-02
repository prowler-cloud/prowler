from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_base_permissions_strict:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict import (
                organization_base_permissions_strict,
            )

            check = organization_base_permissions_strict()
            result = check.execute()
            assert len(result) == 0

    def test_organization_base_permissions_none(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                base_permissions="none",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict import (
                organization_base_permissions_strict,
            )

            check = organization_base_permissions_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has strict base repository permission set to 'none'."
            )

    def test_organization_base_permissions_read(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                base_permissions="read",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict import (
                organization_base_permissions_strict,
            )

            check = organization_base_permissions_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has strict base repository permission set to 'read'."
            )

    def test_organization_base_permissions_write(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                base_permissions="write",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict import (
                organization_base_permissions_strict,
            )

            check = organization_base_permissions_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has base repository permission set to 'write' which is not strict (should be 'read' or 'none')."
            )

    def test_organization_base_permissions_admin(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                base_permissions="admin",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict import (
                organization_base_permissions_strict,
            )

            check = organization_base_permissions_strict()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == "test-organization"
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} has base repository permission set to 'admin' which is not strict (should be 'read' or 'none')."
            )

    def test_organization_base_permissions_null(self):
        """Test that organizations with null base_permissions are skipped."""
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                base_permissions=None,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict import (
                organization_base_permissions_strict,
            )

            check = organization_base_permissions_strict()
            result = check.execute()
            assert len(result) == 0

    def test_multiple_organizations_mixed_permissions(self):
        """Test multiple organizations with different permission levels."""
        organization_client = mock.MagicMock
        organization_client.organizations = {
            1: Org(
                id=1,
                name="strict-org-1",
                mfa_required=True,
                base_permissions="none",
            ),
            2: Org(
                id=2,
                name="strict-org-2",
                mfa_required=True,
                base_permissions="read",
            ),
            3: Org(
                id=3,
                name="non-strict-org",
                mfa_required=True,
                base_permissions="write",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_base_permissions_strict.organization_base_permissions_strict import (
                organization_base_permissions_strict,
            )

            check = organization_base_permissions_strict()
            result = check.execute()
            assert len(result) == 3
            
            # Find results by resource_id
            results_by_id = {r.resource_id: r for r in result}
            
            # Check strict org 1 (none)
            assert results_by_id[1].status == "PASS"
            assert "none" in results_by_id[1].status_extended
            
            # Check strict org 2 (read)
            assert results_by_id[2].status == "PASS"
            assert "read" in results_by_id[2].status_extended
            
            # Check non-strict org (write)
            assert results_by_id[3].status == "FAIL"
            assert "write" in results_by_id[3].status_extended
