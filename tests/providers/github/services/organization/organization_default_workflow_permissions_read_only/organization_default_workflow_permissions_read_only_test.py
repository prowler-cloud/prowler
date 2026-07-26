from unittest import mock

from prowler.providers.github.services.organization.organization_service import Org
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_default_workflow_permissions_read_only:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only import (
                organization_default_workflow_permissions_read_only,
            )

            check = organization_default_workflow_permissions_read_only()
            result = check.execute()
            assert len(result) == 0

    def test_organization_default_workflow_permissions_unknown(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {
            1: Org(
                id=1,
                name="test-organization",
                default_workflow_permissions=None,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only import (
                organization_default_workflow_permissions_read_only,
            )

            check = organization_default_workflow_permissions_read_only()
            result = check.execute()
            assert len(result) == 0

    def test_organization_default_workflow_permissions_write(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                default_workflow_permissions="write",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only import (
                organization_default_workflow_permissions_read_only,
            )

            check = organization_default_workflow_permissions_read_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Organization {org_name} grants workflows a default GITHUB_TOKEN with write permissions."
            )

    def test_organization_default_workflow_permissions_read(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                default_workflow_permissions="read",
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_default_workflow_permissions_read_only.organization_default_workflow_permissions_read_only import (
                organization_default_workflow_permissions_read_only,
            )

            check = organization_default_workflow_permissions_read_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Organization {org_name} grants workflows a read-only default GITHUB_TOKEN."
            )
