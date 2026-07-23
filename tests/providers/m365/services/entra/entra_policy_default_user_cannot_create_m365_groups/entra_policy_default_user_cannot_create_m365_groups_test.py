from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    GROUP_UNIFIED_SETTINGS_TEMPLATE_ID,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_m365_groups.entra_policy_default_user_cannot_create_m365_groups"


class Test_entra_policy_default_user_cannot_create_m365_groups:
    def _run(self, directory_settings):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_policy_default_user_cannot_create_m365_groups.entra_policy_default_user_cannot_create_m365_groups import (
                entra_policy_default_user_cannot_create_m365_groups,
            )

            entra_client.directory_settings = directory_settings
            return entra_policy_default_user_cannot_create_m365_groups().execute()

    def test_template_absent(self):
        result = self._run({})
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_group_creation_enabled(self):
        result = self._run(
            {GROUP_UNIFIED_SETTINGS_TEMPLATE_ID: {"EnableGroupCreation": "true"}}
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_group_creation_disabled(self):
        result = self._run(
            {GROUP_UNIFIED_SETTINGS_TEMPLATE_ID: {"EnableGroupCreation": "false"}}
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
