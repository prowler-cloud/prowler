from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_teams_external_file_sharing_restricted:
    def test_file_sharing_no_restricted(self):
        teams_client = mock.MagicMock()
        teams_client.audited_tenant = "audited_tenant"
        teams_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_external_file_sharing_restricted.teams_external_file_sharing_restricted.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_external_file_sharing_restricted.teams_external_file_sharing_restricted import (
                teams_external_file_sharing_restricted,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                CloudStorageSettings,
                TeamsSettings,
            )

            teams_client.teams_settings = TeamsSettings(
                cloud_storage_settings=CloudStorageSettings(
                    allow_box=True,
                    allow_drop_box=True,
                    allow_egnyte=True,
                    allow_google_drive=True,
                    allow_share_file=True,
                )
            )

            teams_client.audit_config = {"allowed_cloud_storage_services": []}

            check = teams_external_file_sharing_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "External file sharing is not restricted to only approved cloud storage services."
            )
            assert (
                result[0].resource
                == teams_client.teams_settings.cloud_storage_settings.dict()
            )
            assert result[0].resource_name == "Cloud Storage Settings"
            assert result[0].resource_id == "cloudStorageSettings"
            assert result[0].location == "global"

    def test_file_sharing_restricted(self):
        teams_client = mock.MagicMock()
        teams_client.audited_tenant = "audited_tenant"
        teams_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_microsoft_teams"
            ),
            mock.patch(
                "prowler.providers.m365.services.teams.teams_external_file_sharing_restricted.teams_external_file_sharing_restricted.teams_client",
                new=teams_client,
            ),
        ):
            from prowler.providers.m365.services.teams.teams_external_file_sharing_restricted.teams_external_file_sharing_restricted import (
                teams_external_file_sharing_restricted,
            )
            from prowler.providers.m365.services.teams.teams_service import (
                CloudStorageSettings,
                TeamsSettings,
            )

            teams_client.teams_settings = TeamsSettings(
                cloud_storage_settings=CloudStorageSettings(
                    allow_box=True,
                    allow_drop_box=True,
                    allow_egnyte=False,
                    allow_google_drive=True,
                    allow_share_file=True,
                )
            )

            teams_client.audit_config = {
                "allowed_cloud_storage_services": [
                    "allow_box",
                    "allow_drop_box",
                    # "allow_egnyte",
                    "allow_google_drive",
                    "allow_share_file",
                ]
            }

            check = teams_external_file_sharing_restricted()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "External file sharing is restricted to only approved cloud storage services."
            )
            assert (
                result[0].resource
                == teams_client.teams_settings.cloud_storage_settings.dict()
            )
            assert result[0].resource_name == "Cloud Storage Settings"
            assert result[0].resource_id == "cloudStorageSettings"
            assert result[0].location == "global"
