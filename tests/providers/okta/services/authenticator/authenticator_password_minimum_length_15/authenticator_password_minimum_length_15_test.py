from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.authenticator.authenticator_fixtures import (
    build_authenticator_client,
    password_policy,
)

CHECK_PATH = (
    "prowler.providers.okta.services.authenticator."
    "authenticator_password_minimum_length_15.authenticator_password_minimum_length_15.authenticator_client"
)


def _run_check(authenticator_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=authenticator_client),
    ):
        from prowler.providers.okta.services.authenticator.authenticator_password_minimum_length_15.authenticator_password_minimum_length_15 import (
            authenticator_password_minimum_length_15,
        )

        return authenticator_password_minimum_length_15().execute()


class Test_authenticator_password_minimum_length_15:
    def test_no_active_password_policies_fails(self):
        findings = _run_check(build_authenticator_client({}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Password Policies" in findings[0].status_extended

    def test_compliant_password_policy_passes(self):
        policy = password_policy(min_length=15)
        findings = _run_check(build_authenticator_client({policy.id: policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == policy.id

    def test_non_compliant_password_policy_fails(self):
        policy = password_policy(min_length=14)
        findings = _run_check(build_authenticator_client({policy.id: policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert findings[0].resource_id == policy.id

    def test_multiple_active_policies_emit_one_finding_each(self):
        compliant = password_policy(policy_id="pol-good", name="Strict", min_length=15)
        weak = password_policy(
            policy_id="pol-weak", name="Weak", min_length=8, priority=2
        )
        findings = _run_check(
            build_authenticator_client({compliant.id: compliant, weak.id: weak})
        )
        assert len(findings) == 2
        by_name = {finding.resource_name: finding for finding in findings}
        assert by_name["Strict"].status == "PASS"
        assert by_name["Weak"].status == "FAIL"
