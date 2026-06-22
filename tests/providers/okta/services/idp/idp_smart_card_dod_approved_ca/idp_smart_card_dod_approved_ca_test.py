from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.idp.idp_fixtures import (
    build_idp_client,
    non_smart_card_idp,
    smart_card_idp,
)

CHECK_PATH = (
    "prowler.providers.okta.services.idp."
    "idp_smart_card_dod_approved_ca.idp_smart_card_dod_approved_ca.idp_client"
)

DOD_PKI_ISSUER = "CN=DoD ID CA-59, OU=PKI, OU=DoD, O=U.S. Government, C=US"
ECA_ISSUER = "CN=ECA Root CA 4, OU=ECA, O=U.S. Government, C=US"
NON_DOD_ISSUER = "CN=ACME Internal Root, O=Acme Corp, C=US"


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=client),
    ):
        from prowler.providers.okta.services.idp.idp_smart_card_dod_approved_ca.idp_smart_card_dod_approved_ca import (
            idp_smart_card_dod_approved_ca,
        )

        return idp_smart_card_dod_approved_ca().execute()


class Test_idp_smart_card_dod_approved_ca:
    def test_pass_when_active_idp_chain_matches_dod_pki_pattern(self):
        idp = smart_card_idp(name="CAC", issuer=DOD_PKI_ISSUER, kid="kid-x")
        client = build_idp_client(identity_providers={idp.id: idp})
        findings = _run_check(client)
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "OU=DoD" in findings[0].status_extended
        assert DOD_PKI_ISSUER in findings[0].status_extended

    def test_pass_when_active_idp_chain_matches_eca_pattern(self):
        idp = smart_card_idp(name="ECA Partner", issuer=ECA_ISSUER, kid="kid-e")
        client = build_idp_client(identity_providers={idp.id: idp})
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "OU=ECA" in findings[0].status_extended

    def test_manual_when_active_but_issuer_does_not_match_any_pattern(self):
        idp = smart_card_idp(name="Custom", issuer=NON_DOD_ISSUER, kid="kid-c")
        client = build_idp_client(identity_providers={idp.id: idp})
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert NON_DOD_ISSUER in findings[0].status_extended
        assert "okta_dod_approved_ca_issuer_patterns" in findings[0].status_extended

    def test_pass_when_audit_config_pattern_matches(self):
        idp = smart_card_idp(name="Custom DOD", issuer=NON_DOD_ISSUER, kid="kid-c")
        client = build_idp_client(identity_providers={idp.id: idp})
        client.audit_config = {
            "okta_dod_approved_ca_issuer_patterns": [r"CN=ACME Internal Root"]
        }
        findings = _run_check(client)
        assert findings[0].status == "PASS"

    def test_audit_config_overrides_bundled_defaults(self):
        # When the operator supplies a list, the bundled DEFAULT patterns
        # are replaced (not merged) so customers can carve out a strict set.
        idp = smart_card_idp(name="DoD", issuer=DOD_PKI_ISSUER, kid="kid-x")
        client = build_idp_client(identity_providers={idp.id: idp})
        client.audit_config = {
            "okta_dod_approved_ca_issuer_patterns": [r"CN=YourTenantCustomDodCA"]
        }
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"

    def test_malformed_audit_config_pattern_skipped(self):
        # An invalid regex from the operator must not crash the whole check.
        idp = smart_card_idp(name="CAC", issuer=DOD_PKI_ISSUER, kid="kid-x")
        client = build_idp_client(identity_providers={idp.id: idp})
        client.audit_config = {
            "okta_dod_approved_ca_issuer_patterns": [r"[invalid(regex", r"OU=DoD"]
        }
        findings = _run_check(client)
        assert findings[0].status == "PASS"

    def test_fail_when_x509_idp_is_inactive(self):
        idp = smart_card_idp(status="INACTIVE", issuer=DOD_PKI_ISSUER)
        client = build_idp_client(identity_providers={idp.id: idp})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "INACTIVE" in findings[0].status_extended

    def test_fail_when_no_smart_card_idp_configured(self):
        client = build_idp_client(identity_providers={"saml": non_smart_card_idp()})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert (
            "No Smart Card (X509) Identity Providers are configured"
            in findings[0].status_extended
        )
        assert "mutelist" in findings[0].status_extended

    def test_manual_when_idps_scope_missing(self):
        client = build_idp_client(
            missing_scope={"identity_providers": "okta.idps.read"}
        )
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert "okta.idps.read" in findings[0].status_extended

    def test_multiple_x509_idps_yield_one_finding_each(self):
        idp_a = smart_card_idp(idp_id="0oa-a", name="A", issuer=DOD_PKI_ISSUER)
        idp_b = smart_card_idp(
            idp_id="0oa-b", name="B", status="INACTIVE", issuer=DOD_PKI_ISSUER
        )
        client = build_idp_client(identity_providers={idp_a.id: idp_a, idp_b.id: idp_b})
        findings = _run_check(client)
        assert len(findings) == 2
        # We don't strictly assert ordering — just that both are covered.
        statuses = sorted(f.status for f in findings)
        assert statuses == ["FAIL", "PASS"]
