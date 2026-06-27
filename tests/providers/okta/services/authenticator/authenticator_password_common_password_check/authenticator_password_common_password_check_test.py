from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.authenticator.authenticator_fixtures import (
    build_authenticator_client,
    password_policy,
)

CHECK_PATH = (
    "prowler.providers.okta.services.authenticator."
    "authenticator_password_common_password_check.authenticator_password_common_password_check.authenticator_client"
)


def _run_check(authenticator_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=authenticator_client),
    ):
        from prowler.providers.okta.services.authenticator.authenticator_password_common_password_check.authenticator_password_common_password_check import (
            authenticator_password_common_password_check,
        )

        return authenticator_password_common_password_check().execute()


class Test_authenticator_password_common_password_check:
    def test_no_active_password_policies_fails(self):
        findings = _run_check(build_authenticator_client({}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Password Policies" in findings[0].status_extended

    def test_missing_password_policies_scope_is_manual(self):
        findings = _run_check(
            build_authenticator_client(
                {},
                missing_scope={"password_policies": "okta.policies.read"},
            )
        )
        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert "okta.policies.read" in findings[0].status_extended

    def test_compliant_password_policy_passes(self):
        policy = password_policy(common_password_check=True)
        findings = _run_check(build_authenticator_client({policy.id: policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == policy.id

    def test_non_compliant_password_policy_fails(self):
        policy = password_policy(common_password_check=False)
        findings = _run_check(build_authenticator_client({policy.id: policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert findings[0].resource_id == policy.id
