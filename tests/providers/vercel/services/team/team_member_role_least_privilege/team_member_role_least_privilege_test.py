from unittest import mock

from prowler.providers.vercel.services.team.team_service import (
    SAMLConfig,
    VercelTeam,
    VercelTeamMember,
)
from tests.providers.vercel.vercel_fixtures import (
    TEAM_ID,
    TEAM_NAME,
    TEAM_SLUG,
    set_mocked_vercel_provider,
)


class Test_team_member_role_least_privilege:
    def test_no_teams(self):
        team_client = mock.MagicMock
        team_client.teams = {}
        team_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege import (
                team_member_role_least_privilege,
            )

            check = team_member_role_least_privilege()
            result = check.execute()
            assert len(result) == 0

    def test_member_least_privilege(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="disabled", enforced=False),
                members=[
                    VercelTeamMember(
                        id="member_1",
                        email="member@example.com",
                        role="MEMBER",
                        status="active",
                    ),
                ],
            )
        }
        team_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege import (
                team_member_role_least_privilege,
            )

            check = team_member_role_least_privilege()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} has 0 owner(s) out of 1 active members. Small team with minimum required owner — least privilege threshold not applicable."
            )
            assert result[0].team_id == ""

    def test_small_team_single_owner(self):
        """Small team (<5 members) with 1 owner gets a PASS (small team exception)."""
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="disabled", enforced=False),
                members=[
                    VercelTeamMember(
                        id="member_1",
                        email="member@example.com",
                        role="OWNER",
                        status="active",
                    ),
                ],
            )
        }
        team_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege import (
                team_member_role_least_privilege,
            )

            check = team_member_role_least_privilege()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} has 1 owner(s) out of 1 active members. Small team with minimum required owner — least privilege threshold not applicable."
            )
            assert result[0].team_id == ""

    def test_large_team_too_many_owners(self):
        """Large team (>=5 members) with >20% owners gets a FAIL."""
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="disabled", enforced=False),
                members=[
                    VercelTeamMember(
                        id=f"member_{i}",
                        email=f"member{i}@example.com",
                        role="OWNER" if i <= 2 else "MEMBER",
                        status="active",
                    )
                    for i in range(1, 6)
                ],
            )
        }
        team_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege import (
                team_member_role_least_privilege,
            )

            check = team_member_role_least_privilege()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "FAIL"
            assert "40% exceeds the 20% threshold" in result[0].status_extended
            assert result[0].team_id == ""

    def test_large_team_exceeds_max_owners(self):
        """Large team within percentage but exceeding max_owners gets a FAIL."""
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="disabled", enforced=False),
                members=[
                    VercelTeamMember(
                        id=f"member_{i}",
                        email=f"member{i}@example.com",
                        role="OWNER" if i <= 4 else "MEMBER",
                        status="active",
                    )
                    for i in range(1, 21)
                ],
            )
        }
        team_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege import (
                team_member_role_least_privilege,
            )

            check = team_member_role_least_privilege()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "4 owners exceeds the maximum of 3" in result[0].status_extended

    def test_custom_thresholds(self):
        """Custom thresholds via audit_config are respected."""
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="disabled", enforced=False),
                members=[
                    VercelTeamMember(
                        id=f"member_{i}",
                        email=f"member{i}@example.com",
                        role="OWNER" if i <= 2 else "MEMBER",
                        status="active",
                    )
                    for i in range(1, 6)
                ],
            )
        }
        team_client.audit_config = {
            "max_owner_percentage": 50,
            "max_owners": 5,
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_member_role_least_privilege.team_member_role_least_privilege import (
                team_member_role_least_privilege,
            )

            check = team_member_role_least_privilege()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "within the configured thresholds (50% / max 5 owners)"
                in result[0].status_extended
            )
