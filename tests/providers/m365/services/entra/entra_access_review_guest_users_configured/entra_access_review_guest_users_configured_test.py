from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AccessReviewDefinition,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_access_review_guest_users_configured.entra_access_review_guest_users_configured"


def _definition(
    status="InProgress",
    scope_query="/users?$filter=(userType eq 'Guest')",
    default_decision="Deny",
    auto_apply_enabled=True,
    mail_notifications_enabled=True,
    reminders_enabled=True,
):
    return AccessReviewDefinition(
        id="ar1",
        display_name="Guest Review",
        status=status,
        scope_query=scope_query,
        default_decision=default_decision,
        auto_apply_enabled=auto_apply_enabled,
        mail_notifications_enabled=mail_notifications_enabled,
        reminders_enabled=reminders_enabled,
    )


class Test_entra_access_review_guest_users_configured:
    def _run(self, definitions):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_access_review_guest_users_configured.entra_access_review_guest_users_configured import (
                entra_access_review_guest_users_configured,
            )

            entra_client.access_review_definitions = definitions
            return entra_access_review_guest_users_configured().execute()

    def test_no_definitions(self):
        result = self._run([])
        assert result[0].status == "FAIL"

    def test_active_failclosed_guest_review(self):
        result = self._run([_definition()])
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Access review 'Guest Review' for guest users is active and fail-closed."
        )

    def test_not_active(self):
        result = self._run([_definition(status="Completed")])
        assert result[0].status == "FAIL"

    def test_not_fail_closed(self):
        # Active guest review but does nothing on non-response -> FAIL.
        result = self._run(
            [_definition(default_decision="None", auto_apply_enabled=False)]
        )
        assert result[0].status == "FAIL"

    def test_not_guest_scope(self):
        result = self._run([_definition(scope_query="/roleManagement/directory")])
        assert result[0].status == "FAIL"
