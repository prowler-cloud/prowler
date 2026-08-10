from unittest import mock

import pytest

from prowler.providers.m365.services.entra.entra_service import (
    AccessReviewDefinition,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_access_review_privileged_roles_configured.entra_access_review_privileged_roles_configured"


def _definition(
    status="InProgress",
    scope_query="",
    resource_scope_queries=None,
    default_decision="None",
    auto_apply_enabled=True,
    mail_notifications_enabled=True,
    reminders_enabled=True,
    recurrence_pattern_type="absoluteMonthly",
    recurrence_range_type="noEnd",
    has_primary_reviewers=True,
):
    return AccessReviewDefinition(
        id="ar1",
        display_name="Privileged Roles Review",
        status=status,
        scope_query=scope_query,
        resource_scope_queries=(
            resource_scope_queries
            if resource_scope_queries is not None
            else ["/roleManagement/directory/roleDefinitions/62e90394-..."]
        ),
        default_decision=default_decision,
        auto_apply_enabled=auto_apply_enabled,
        mail_notifications_enabled=mail_notifications_enabled,
        reminders_enabled=reminders_enabled,
        recurrence_pattern_type=recurrence_pattern_type,
        recurrence_range_type=recurrence_range_type,
        has_primary_reviewers=has_primary_reviewers,
    )


class Test_entra_access_review_privileged_roles_configured:
    def _run(self, definitions):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_access_review_privileged_roles_configured.entra_access_review_privileged_roles_configured import (
                entra_access_review_privileged_roles_configured,
            )

            entra_client.access_review_definitions = definitions
            return entra_access_review_privileged_roles_configured().execute()

    def test_no_definitions(self):
        assert self._run([])[0].status == "FAIL"

    def test_active_fail_closed_privileged(self):
        # Role reference lives in resource scopes (not top-level scope.query).
        result = self._run([_definition()])
        assert result[0].status == "PASS"

    def test_deny_default_decision(self):
        result = self._run([_definition(default_decision="Deny")])
        assert result[0].status == "FAIL"

    def test_guest_review_ignored(self):
        result = self._run(
            [
                _definition(
                    scope_query="/users?$filter=(userType eq 'Guest')",
                    resource_scope_queries=[],
                )
            ]
        )
        assert result[0].status == "FAIL"

    @pytest.mark.parametrize(
        "definition_overrides",
        [
            {"recurrence_pattern_type": None},
            {"recurrence_pattern_type": "daily"},
            {"recurrence_range_type": None},
            {"recurrence_range_type": "numbered"},
            {"has_primary_reviewers": False},
        ],
    )
    def test_invalid_recurrence_or_missing_reviewers(self, definition_overrides):
        result = self._run([_definition(**definition_overrides)])
        assert result[0].status == "FAIL"
