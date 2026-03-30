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


class Test_team_no_stale_invitations:
    def test_no_teams(self):
        team_client = mock.MagicMock
        team_client.audit_config = {"stale_invitation_threshold_days": 30}
        team_client.teams = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_no_stale_invitations.team_no_stale_invitations.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_no_stale_invitations.team_no_stale_invitations import (
                team_no_stale_invitations,
            )

            check = team_no_stale_invitations()
            result = check.execute()
            assert len(result) == 0

    def test_no_stale_invitations(self):
        team_client = mock.MagicMock
        team_client.audit_config = {"stale_invitation_threshold_days": 30}
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
                        created_at=datetime.now(timezone.utc) - timedelta(days=5),
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
                "prowler.providers.vercel.services.team.team_no_stale_invitations.team_no_stale_invitations.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_no_stale_invitations.team_no_stale_invitations import (
                team_no_stale_invitations,
            )

            check = team_no_stale_invitations()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} has no stale pending invitations older than 30 days."
            )
            assert result[0].team_id == ""

    def test_stale_invitation(self):
        team_client = mock.MagicMock
        team_client.audit_config = {"stale_invitation_threshold_days": 30}
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                members=[
                    VercelTeamMember(
                        id="member_1",
                        email="old_invite@example.com",
                        role="MEMBER",
                        status="invited",
                        created_at=datetime.now(timezone.utc) - timedelta(days=60),
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
                "prowler.providers.vercel.services.team.team_no_stale_invitations.team_no_stale_invitations.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_no_stale_invitations.team_no_stale_invitations import (
                team_no_stale_invitations,
            )

            check = team_no_stale_invitations()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} has 1 stale pending invitation(s) older than 30 days."
            )
            assert result[0].team_id == ""
