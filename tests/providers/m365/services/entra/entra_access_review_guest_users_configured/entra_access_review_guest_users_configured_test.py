from unittest import mock

import pytest

from prowler.providers.m365.services.entra.entra_service import (
    AccessReviewDefinition,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_access_review_guest_users_configured.entra_access_review_guest_users_configured"


def _definition(
    status="InProgress",
    scope_query="/users?$filter=(userType eq 'Guest')",
    principal_scope_queries=None,
    default_decision="Deny",
    default_decision_enabled=True,
    auto_apply_enabled=True,
    mail_notifications_enabled=True,
    reminders_enabled=True,
    recurrence_pattern_type="weekly",
    recurrence_range_type="noEnd",
    has_primary_reviewers=True,
):
    definition = {
        "id": "ar1",
        "display_name": "Guest Review",
        "status": status,
        "scope_query": scope_query,
        "principal_scope_queries": principal_scope_queries or [],
        "default_decision": default_decision,
        "auto_apply_enabled": auto_apply_enabled,
        "mail_notifications_enabled": mail_notifications_enabled,
        "reminders_enabled": reminders_enabled,
        "recurrence_pattern_type": recurrence_pattern_type,
        "recurrence_range_type": recurrence_range_type,
        "has_primary_reviewers": has_primary_reviewers,
    }
    if default_decision_enabled is not None:
        definition["default_decision_enabled"] = default_decision_enabled
    return AccessReviewDefinition(**definition)


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
            == "Access review 'Guest Review' for guest users is active, recurring, "
            "reviewer-assigned, and fail-closed."
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

    @pytest.mark.parametrize("default_decision_enabled", [False, None])
    def test_default_decision_not_enabled(self, default_decision_enabled):
        result = self._run(
            [_definition(default_decision_enabled=default_decision_enabled)]
        )
        assert result[0].status == "FAIL"

    def test_not_guest_scope(self):
        result = self._run([_definition(scope_query="/roleManagement/directory")])
        assert result[0].status == "FAIL"

    def test_guest_filter_in_principal_scopes(self):
        # Portal-created reviews keep the guest filter in principalScopes and
        # leave the top-level scope query empty.
        result = self._run(
            [
                _definition(
                    scope_query="",
                    principal_scope_queries=["/users?$filter=(userType eq 'Guest')"],
                )
            ]
        )
        assert result[0].status == "PASS"

    def test_url_encoded_guest_filter(self):
        result = self._run(
            [_definition(scope_query="/users?$filter=userType%20eq%20%27Guest%27")]
        )
        assert result[0].status == "PASS"

    def test_mixed_case_guest_filter(self):
        result = self._run(
            [_definition(scope_query="/users?$filter=(USERTYPE EQ 'guest')")]
        )
        assert result[0].status == "PASS"

    @pytest.mark.parametrize(
        "scope_query",
        [
            "/users?$filter=not(userType eq 'Guest')",
            "/users?$filter=(userType ne 'Guest')",
            "/users?$filter=displayName eq 'Guest account'",
            "/groups/guest-review-members",
        ],
    )
    def test_incidental_guest_text_does_not_target_guests(self, scope_query):
        result = self._run([_definition(scope_query=scope_query)])
        assert result[0].status == "FAIL"

    @pytest.mark.parametrize(
        "definition_overrides",
        [
            {"recurrence_pattern_type": None},
            {"recurrence_pattern_type": "daily"},
            {"recurrence_range_type": None},
            {"recurrence_range_type": "endDate"},
            {"has_primary_reviewers": False},
        ],
    )
    def test_invalid_recurrence_or_missing_reviewers(self, definition_overrides):
        result = self._run([_definition(**definition_overrides)])
        assert result[0].status == "FAIL"
