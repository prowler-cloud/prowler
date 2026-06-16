from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.authenticator.authenticator_fixtures import (
    authenticator,
    build_authenticator_client,
)

CHECK_PATH = (
    "prowler.providers.okta.services.authenticator."
    "authenticator_okta_verify_fips_compliant."
    "authenticator_okta_verify_fips_compliant.authenticator_client"
)


def _run_check(authenticator_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=authenticator_client),
    ):
        from prowler.providers.okta.services.authenticator.authenticator_okta_verify_fips_compliant.authenticator_okta_verify_fips_compliant import (
            authenticator_okta_verify_fips_compliant,
        )

        return authenticator_okta_verify_fips_compliant().execute()


class Test_authenticator_okta_verify_fips_compliant:
    def test_okta_verify_fips_required_passes(self):
        okta_verify = authenticator(key="okta_verify", fips="REQUIRED")
        findings = _run_check(
            build_authenticator_client(authenticators={okta_verify.id: okta_verify})
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == okta_verify.id

    def test_okta_verify_without_fips_required_fails(self):
        okta_verify = authenticator(key="okta_verify", fips="OPTIONAL")
        findings = _run_check(
            build_authenticator_client(authenticators={okta_verify.id: okta_verify})
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "FIPS" in findings[0].status_extended

    def test_missing_okta_verify_fails(self):
        findings = _run_check(build_authenticator_client(authenticators={}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "Okta Verify authenticator is missing." in findings[0].status_extended

    def test_inactive_okta_verify_surfaces_current_status(self):
        okta_verify = authenticator(key="okta_verify", status="INACTIVE")
        findings = _run_check(
            build_authenticator_client(authenticators={okta_verify.id: okta_verify})
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "INACTIVE" in findings[0].status_extended

    def test_missing_authenticators_scope_is_manual(self):
        findings = _run_check(
            build_authenticator_client(
                authenticators={},
                missing_scope={"authenticators": "okta.authenticators.read"},
            )
        )
        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert "okta.authenticators.read" in findings[0].status_extended
