from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.github.services.organization.organization_service import (
    Org,
    OrgMember,
)
from tests.providers.github.github_fixtures import set_mocked_github_provider


class Test_organization_members_inactive:
    def test_no_organizations(self):
        organization_client = mock.MagicMock
        organization_client.organizations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive import (
                organization_members_inactive,
            )

            check = organization_members_inactive()
            result = check.execute()
            assert len(result) == 0

    def test_organization_with_no_members(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                members=[],
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive import (
                organization_members_inactive,
            )

            check = organization_members_inactive()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert "no inactive members detected" in result[0].status_extended

    def test_organization_with_active_members(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                members=[
                    OrgMember(
                        id=123,
                        login="active_user",
                        last_activity=datetime.now(timezone.utc) - timedelta(days=5),
                    )
                ],
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive import (
                organization_members_inactive,
            )

            check = organization_members_inactive()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "PASS"
            assert "no inactive members detected" in result[0].status_extended

    def test_organization_with_inactive_members_no_activity(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                members=[
                    OrgMember(
                        id=123,
                        login="inactive_user",
                        last_activity=None,
                    )
                ],
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive import (
                organization_members_inactive,
            )

            check = organization_members_inactive()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert "1 inactive members" in result[0].status_extended
            assert "inactive_user" in result[0].status_extended

    def test_organization_with_inactive_members_old_activity(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                members=[
                    OrgMember(
                        id=123,
                        login="old_inactive_user",
                        last_activity=datetime.now(timezone.utc) - timedelta(days=35),
                    )
                ],
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive import (
                organization_members_inactive,
            )

            check = organization_members_inactive()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert "1 inactive members" in result[0].status_extended
            assert "old_inactive_user" in result[0].status_extended

    def test_organization_with_mixed_members(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                members=[
                    OrgMember(
                        id=123,
                        login="active_member",
                        last_activity=datetime.now(timezone.utc) - timedelta(days=5),
                    ),
                    OrgMember(
                        id=124,
                        login="inactive_user1",
                        last_activity=None,
                    ),
                    OrgMember(
                        id=125,
                        login="inactive_user2",
                        last_activity=datetime.now(timezone.utc) - timedelta(days=35),
                    ),
                ],
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive import (
                organization_members_inactive,
            )

            check = organization_members_inactive()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert "2 inactive members" in result[0].status_extended
            assert "inactive_user1" in result[0].status_extended
            assert "inactive_user2" in result[0].status_extended
            assert "active_member" not in result[0].status_extended

    def test_organization_with_many_inactive_members(self):
        organization_client = mock.MagicMock
        org_name = "test-organization"
        # Create many inactive members to test truncation
        inactive_members = []
        for i in range(10):
            inactive_members.append(
                OrgMember(
                    id=100 + i,
                    login=f"inactive_user_{i}",
                    last_activity=None,
                )
            )

        organization_client.organizations = {
            1: Org(
                id=1,
                name=org_name,
                mfa_required=True,
                members=inactive_members,
            ),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_github_provider(),
            ),
            mock.patch(
                "prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive.organization_client",
                new=organization_client,
            ),
        ):
            from prowler.providers.github.services.organization.organization_members_inactive.organization_members_inactive import (
                organization_members_inactive,
            )

            check = organization_members_inactive()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == 1
            assert result[0].resource_name == org_name
            assert result[0].status == "FAIL"
            assert "10 inactive members" in result[0].status_extended
            assert "..." in result[0].status_extended  # Should truncate after 5 names
