from unittest import mock

from prowler.providers.vercel.services.team.team_service import SAMLConfig, VercelTeam
from tests.providers.vercel.vercel_fixtures import (
    TEAM_ID,
    TEAM_NAME,
    TEAM_SLUG,
    set_mocked_vercel_provider,
)


class Test_team_saml_sso_enforced:
    def test_no_teams(self):
        team_client = mock.MagicMock
        team_client.teams = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced import (
                team_saml_sso_enforced,
            )

            check = team_saml_sso_enforced()
            result = check.execute()
            assert len(result) == 0

    def test_saml_enforced(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="enabled", enforced=True),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced import (
                team_saml_sso_enforced,
            )

            check = team_saml_sso_enforced()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} enforces SAML SSO for all members."
            )
            assert result[0].team_id == ""

    def test_saml_enabled_not_enforced(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="enabled", enforced=False),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced import (
                team_saml_sso_enforced,
            )

            check = team_saml_sso_enforced()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} has SAML SSO enabled but does not enforce it. Members can still authenticate without SSO. This feature is only available on Vercel Pro/Enterprise plans."
            )
            assert result[0].team_id == ""

    def test_saml_disabled(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                saml=SAMLConfig(status="disabled", enforced=False),
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_saml_sso_enforced.team_saml_sso_enforced import (
                team_saml_sso_enforced,
            )

            check = team_saml_sso_enforced()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} does not have SAML SSO enforced. This feature is only available on Vercel Pro/Enterprise plans."
            )
            assert result[0].team_id == ""
