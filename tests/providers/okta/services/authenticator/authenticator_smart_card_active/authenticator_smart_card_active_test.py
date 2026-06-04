from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.authenticator.authenticator_fixtures import (
    authenticator,
    build_authenticator_client,
)

CHECK_PATH = (
    "prowler.providers.okta.services.authenticator."
    "authenticator_smart_card_active.authenticator_smart_card_active.authenticator_client"
)


def _run_check(authenticator_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=authenticator_client),
    ):
        from prowler.providers.okta.services.authenticator.authenticator_smart_card_active.authenticator_smart_card_active import (
            authenticator_smart_card_active,
        )

        return authenticator_smart_card_active().execute()


class Test_authenticator_smart_card_active:
    def test_smart_card_active_passes(self):
        smart_card = authenticator(
            auth_id="aut-smart-card",
            key="smart_card_idp",
            name="Smart Card IdP",
            status="ACTIVE",
        )
        findings = _run_check(
            build_authenticator_client(authenticators={smart_card.id: smart_card})
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == smart_card.id

    def test_missing_smart_card_fails(self):
        findings = _run_check(build_authenticator_client(authenticators={}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "not active" in findings[0].status_extended

    def test_inactive_smart_card_fails(self):
        smart_card = authenticator(
            auth_id="aut-smart-card",
            key="smart_card_idp",
            name="Smart Card IdP",
            status="INACTIVE",
        )
        findings = _run_check(
            build_authenticator_client(authenticators={smart_card.id: smart_card})
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "INACTIVE" in findings[0].status_extended
