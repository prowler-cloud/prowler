from pathlib import Path
from unittest.mock import MagicMock

import pytest

from prowler.lib.check.models import CheckMetadata
from prowler.providers.googleworkspace.services.rules import rules_service
from prowler.providers.googleworkspace.services.rules.lib.alerts import (
    evaluate_system_defined_alert,
)
from prowler.providers.googleworkspace.services.rules.rules_service import (
    SystemDefinedAlert,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)

RULE_NAME = "Leaked password"
OTHER_RULE = "Suspicious login"


def make_client(alerts, policies_fetched=True):
    client = MagicMock()
    client.provider = set_mocked_googleworkspace_provider()
    client.policies_fetched = policies_fetched
    client.system_defined_alerts = alerts
    return client


def configured(**overrides):
    values = dict(
        display_name=RULE_NAME,
        state="ACTIVE",
        severity="MEDIUM",
        email_notifications_enabled=True,
        all_super_admins=True,
    )
    values.update(overrides)
    return SystemDefinedAlert(**values)


# Real metadata: CheckReportGoogleWorkspace validates it, a mock will not do.
# Loaded from the file rather than from the check class, whose module import
# builds the service client and needs a live provider.
METADATA_FILE = (
    Path(rules_service.__file__).parent
    / "rules_leaked_password_alert_configured"
    / "rules_leaked_password_alert_configured.metadata.json"
)
METADATA = CheckMetadata.parse_file(METADATA_FILE).json()


def run(alerts, minimum_severity="MEDIUM", policies_fetched=True):
    return evaluate_system_defined_alert(
        make_client(alerts, policies_fetched), METADATA, RULE_NAME, minimum_severity
    )


class TestEvaluateSystemDefinedAlert:
    def test_evaluates_only_the_requested_rule(self):
        findings = run(
            [
                configured(display_name=OTHER_RULE, state="INACTIVE", severity=None),
                configured(),
                configured(display_name="Government-backed attacks", severity="HIGH"),
            ]
        )

        assert len(findings) == 1
        assert findings[0].resource_name == RULE_NAME
        assert findings[0].status == "PASS"

    def test_no_finding_when_the_rule_is_absent(self):
        assert run([configured(display_name=OTHER_RULE)]) == []

    def test_no_finding_when_fetch_failed(self):
        assert run([configured()], policies_fetched=False) == []

    @pytest.mark.parametrize("severity", ["MEDIUM", "HIGH"])
    def test_a_severity_above_the_minimum_is_stricter_not_weaker(self, severity):
        findings = run([configured(severity=severity)], "MEDIUM")

        assert findings[0].status == "PASS"

    @pytest.mark.parametrize("severity", ["CRITICAL", "high", "SEVERITY_UNSPECIFIED"])
    def test_an_unrankable_severity_is_not_claimed_to_be_below_the_minimum(
        self, severity
    ):
        """Saying CRITICAL falls short of MEDIUM would be a lie, not a finding"""
        findings = run([configured(severity=severity)], "MEDIUM")

        assert findings[0].status == "FAIL"
        assert f"severity is {severity}, which is not one of" in (
            findings[0].status_extended
        )
        assert f"should be at least {severity}" not in findings[0].status_extended

    def test_reports_the_minimum_severity_on_failure(self):
        findings = run([configured(severity="LOW")], "MEDIUM")

        assert findings[0].status == "FAIL"
        assert "severity is LOW (should be at least MEDIUM)" in (
            findings[0].status_extended
        )

    def test_an_unobserved_rule_left_on_an_active_default_is_manual(self):
        """Google documents no default severity, so it cannot be verified"""
        findings = run([configured(severity=None, from_default=True)])

        assert findings[0].status == "MANUAL"
        assert "was not returned by the API" in findings[0].status_extended

    def test_an_unobserved_rule_that_defaults_to_off_still_fails(self):
        """The OFF default is documented, so it fails whatever the severity is"""
        findings = run([configured(state="INACTIVE", severity=None, from_default=True)])

        assert findings[0].status == "FAIL"
        assert "Google's default for it is OFF" in findings[0].status_extended

    def test_reports_every_failing_condition(self):
        findings = run(
            [
                configured(
                    state="INACTIVE",
                    severity="LOW",
                    email_notifications_enabled=False,
                )
            ]
        )

        extended = findings[0].status_extended
        assert findings[0].status == "FAIL"
        assert "alert is OFF" in extended
        assert "email notifications are disabled" in extended
        assert "severity is LOW" in extended
