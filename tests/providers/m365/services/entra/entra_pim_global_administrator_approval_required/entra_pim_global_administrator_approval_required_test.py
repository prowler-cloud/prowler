from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
    PimRoleApprovalSetting,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_pim_global_administrator_approval_required.entra_pim_global_administrator_approval_required"


class Test_entra_pim_global_administrator_approval_required:
    def _run(self, settings):
        entra_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_pim_global_administrator_approval_required.entra_pim_global_administrator_approval_required import (
                entra_pim_global_administrator_approval_required,
            )

            entra_client.pim_role_approval_settings = settings
            return entra_pim_global_administrator_approval_required().execute()

    def test_no_setting(self):
        assert self._run({}) == []

    def test_approval_required(self):
        result = self._run(
            {
                GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID: PimRoleApprovalSetting(
                    role_definition_id=GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
                    is_approval_required=True,
                    has_approvers=True,
                )
            }
        )
        assert result[0].status == "PASS"

    def test_no_approvers(self):
        result = self._run(
            {
                GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID: PimRoleApprovalSetting(
                    role_definition_id=GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
                    is_approval_required=True,
                    has_approvers=False,
                )
            }
        )
        assert result[0].status == "FAIL"
