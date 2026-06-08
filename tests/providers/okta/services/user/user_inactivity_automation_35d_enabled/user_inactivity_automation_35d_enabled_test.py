from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.user.user_fixtures import (
    ad_idp,
    automation,
    build_user_client,
)

CHECK_PATH = (
    "prowler.providers.okta.services.user."
    "user_inactivity_automation_35d_enabled."
    "user_inactivity_automation_35d_enabled.user_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=client),
    ):
        from prowler.providers.okta.services.user.user_inactivity_automation_35d_enabled.user_inactivity_automation_35d_enabled import (
            user_inactivity_automation_35d_enabled,
        )

        return user_inactivity_automation_35d_enabled().execute()


class Test_user_inactivity_automation_35d_enabled:
    def test_pass_when_compliant_automation_present(self):
        client = build_user_client(
            automations={"auto-1": automation(name="Inactivity 35d")}
        )
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "Inactivity 35d" in findings[0].status_extended
        assert "SUSPENDED" in findings[0].status_extended

    def test_pass_when_lower_threshold(self):
        # Inactivity threshold lower than the default is still compliant.
        client = build_user_client(
            automations={"auto-1": automation(inactivity_days=14)}
        )
        findings = _run_check(client)
        assert findings[0].status == "PASS"

    def test_fail_when_threshold_too_high(self):
        client = build_user_client(
            automations={"auto-1": automation(inactivity_days=90)}
        )
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "inactivity 90d (max 35d)" in findings[0].status_extended

    def test_fail_when_status_inactive(self):
        client = build_user_client(
            automations={"auto-1": automation(status="INACTIVE")}
        )
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "status INACTIVE" in findings[0].status_extended

    def test_fail_when_schedule_inactive(self):
        client = build_user_client(
            automations={"auto-1": automation(schedule_status="INACTIVE")}
        )
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "schedule INACTIVE" in findings[0].status_extended

    def test_fail_when_wrong_lifecycle_action(self):
        client = build_user_client(
            automations={"auto-1": automation(lifecycle_action="ACTIVE")}
        )
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "action ACTIVE" in findings[0].status_extended

    def test_fail_when_no_automations(self):
        client = build_user_client(automations={})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "No Okta Workflows automations" in findings[0].status_extended

    def test_fail_lists_every_missing_piece_for_unfinished_automation(self):
        # Mirrors the real-world case where an admin clicks "Add Automation"
        # in the UI but never configures conditions or actions. The service
        # emits a placeholder UserAutomation so the check FAILs with a
        # specific message instead of pretending the policy doesn't exist.
        from prowler.providers.okta.services.user.user_service import UserAutomation

        shell = UserAutomation(
            id="pol-1",
            name="TestCheck",
            status="INACTIVE",
            schedule_status="INACTIVE",
            inactivity_days=None,
            lifecycle_action=None,
            applies_to_groups=[],
            policy_id="pol-1",
            policy_name="TestCheck",
        )
        client = build_user_client(automations={"pol-1": shell})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        msg = findings[0].status_extended
        assert "TestCheck" in msg
        assert "status INACTIVE" in msg
        assert "schedule INACTIVE" in msg
        assert "no inactivity condition" in msg
        assert "action unset" in msg

    def test_manual_na_when_external_directory_idp_present(self):
        client = build_user_client(
            automations={"auto-1": automation(inactivity_days=90)},  # non-compliant
            external_directory_idps={"0oa-ad": ad_idp(name="Corp AD")},
        )
        findings = _run_check(client)
        # External directory short-circuits to MANUAL N/A regardless of
        # the automations state.
        assert findings[0].status == "MANUAL"
        assert "ACTIVE_DIRECTORY" in findings[0].status_extended
        assert "Corp AD" in findings[0].status_extended

    def test_manual_when_scope_missing(self):
        client = build_user_client(
            missing_scope={
                "automations": "okta.policies.read",
                "identity_providers": None,
            }
        )
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert "okta.policies.read" in findings[0].status_extended

    def test_threshold_overridden_via_audit_config(self):
        client = build_user_client(
            automations={"auto-1": automation(inactivity_days=60)},
            audit_config={"okta_user_inactivity_max_days": 90},
        )
        findings = _run_check(client)
        assert findings[0].status == "PASS"
