from unittest import mock

from prowler.providers.vercel.services.team.team_service import VercelTeam
from tests.providers.vercel.vercel_fixtures import (
    TEAM_ID,
    TEAM_NAME,
    TEAM_SLUG,
    set_mocked_vercel_provider,
)


class Test_team_directory_sync_enabled:
    def test_no_teams(self):
        team_client = mock.MagicMock
        team_client.teams = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled import (
                team_directory_sync_enabled,
            )

            check = team_directory_sync_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_directory_sync_enabled(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                directory_sync_enabled=True,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled import (
                team_directory_sync_enabled,
            )

            check = team_directory_sync_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} has directory sync (SCIM) enabled for automated user provisioning."
            )
            assert result[0].team_id == ""

    def test_directory_sync_disabled(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                directory_sync_enabled=False,
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled import (
                team_directory_sync_enabled,
            )

            check = team_directory_sync_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} does not have directory sync (SCIM) enabled. User provisioning and deprovisioning must be managed manually."
            )
            assert result[0].team_id == ""

    def test_directory_sync_disabled_pro_plan(self):
        team_client = mock.MagicMock
        team_client.teams = {
            TEAM_ID: VercelTeam(
                id=TEAM_ID,
                name=TEAM_NAME,
                slug=TEAM_SLUG,
                directory_sync_enabled=False,
                billing_plan="pro",
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_vercel_provider(),
            ),
            mock.patch(
                "prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled.team_client",
                new=team_client,
            ),
        ):
            from prowler.providers.vercel.services.team.team_directory_sync_enabled.team_directory_sync_enabled import (
                team_directory_sync_enabled,
            )

            check = team_directory_sync_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].resource_id == TEAM_ID
            assert result[0].resource_name == TEAM_NAME
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Team {TEAM_NAME} does not have directory sync (SCIM) enabled. User provisioning and deprovisioning must be managed manually. This may be expected because directory sync (SCIM) is only available on Vercel Enterprise plans."
            )
            assert result[0].team_id == ""
