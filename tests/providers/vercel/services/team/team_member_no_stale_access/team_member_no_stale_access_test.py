from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.vercel.services.team.team_service import (
    VercelTeam,
    VercelTeamMember,
)
from tests.providers.vercel.vercel_fixtures import (
    TEAM_ID,
    TEAM_NAME,
    TEAM_SLUG,
    set_mocked_vercel_provider,
)


class Test_team_member_no_stale_access:
    def test_no_teams(self):
        team_client = mock.MagicMock
        team_client.teams = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access import (
                team_member_no_stale_access,
            )

            check = team_member_no_stale_access()
            result = check.execute()
            assert len(result) == 0

    def test_no_stale_members(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                members=[
                    VercelTeamMember(
                        id="member_1",
                        email="new@example.com",
                        role="MEMBER",
                        status="active",
                        joined_at=datetime.now(timezone.utc) - timedelta(days=30),
                    ),
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access import (
                team_member_no_stale_access,
            )

            check = team_member_no_stale_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "PASS"
            assert "no members with access older" in result[0].status_extended

    def test_stale_member(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                members=[
                    VercelTeamMember(
                        id="member_1",
                        email="old@example.com",
                        role="MEMBER",
                        status="active",
                        joined_at=datetime.now(timezone.utc) - timedelta(days=120),
                    ),
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access import (
                team_member_no_stale_access,
            )

            check = team_member_no_stale_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "FAIL"
            assert "joined more than" in result[0].status_extended

    def test_non_active_member_skipped(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                members=[
                    VercelTeamMember(
                        id="member_1",
                        email="invited@example.com",
                        role="MEMBER",
                        status="invited",
                        joined_at=datetime.now(timezone.utc) - timedelta(days=120),
                    ),
                ],
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_no_stale_access.team_member_no_stale_access import (
                team_member_no_stale_access,
            )

            check = team_member_no_stale_access()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "PASS"
            assert "no members with access older" in result[0].status_extended
