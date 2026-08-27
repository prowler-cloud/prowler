from pathlib import Path
from unittest.mock import MagicMock

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


def run(alerts, severities={"MEDIUM"}, policies_fetched=True):
    return evaluate_system_defined_alert(
        make_client(alerts, policies_fetched), METADATA, RULE_NAME, severities
    )


class TestEvaluateSystemDefinedAlert:
    def test_evaluates_only_the_requested_rule(self):
        """A workspace returns every system rule; only the mapped one is reported"""
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

    def test_accepts_any_of_several_severities(self):
        for severity in ("HIGH", "MEDIUM"):
            findings = run([configured(severity=severity)], {"HIGH", "MEDIUM"})
            assert findings[0].status == "PASS"

    def test_reports_the_accepted_severities_on_failure(self):
        findings = run([configured(severity="LOW")], {"HIGH", "MEDIUM"})

        assert findings[0].status == "FAIL"
        assert "severity is LOW (should be HIGH or MEDIUM)" in (
            findings[0].status_extended
        )

    def test_does_not_blame_the_tenant_for_a_rule_the_api_never_returned(self):
        """Values inferred from Google's defaults were never observed"""
        findings = run([configured(severity=None, from_default=True)])

        assert findings[0].status == "FAIL"
        assert "was not returned by the API" in findings[0].status_extended
        assert "severity is not configured" not in findings[0].status_extended

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
