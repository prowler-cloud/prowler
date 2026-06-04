from unittest import mock

import pytest

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.api_token.api_token_fixtures import (
    api_token,
    build_api_token_client,
)

CHECK_PATH = (
    "prowler.providers.okta.services.apitoken."
    "apitoken_restricted_to_network_zone.apitoken_restricted_to_network_zone.api_token_client"
)


def _run_check(api_token_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=api_token_client),
    ):
        from prowler.providers.okta.services.apitoken.apitoken_restricted_to_network_zone.apitoken_restricted_to_network_zone import (
            apitoken_restricted_to_network_zone,
        )

        return apitoken_restricted_to_network_zone().execute()


class Test_apitoken_restricted_to_network_zone:
    @pytest.mark.parametrize(
        "missing_scope", ["okta.apiTokens.read", "okta.networkZones.read"]
    )
    def test_missing_required_scope_returns_manual(self, missing_scope):
        findings = _run_check(
            build_api_token_client({}, missing_scopes=[missing_scope])
        )
        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert missing_scope in findings[0].status_extended

    def test_no_tokens_returns_no_findings(self):
        findings = _run_check(build_api_token_client({}))
        assert findings == []

    def test_token_restricted_to_known_network_zone_passes(self):
        token = api_token(network_connection="ZONE", network_includes=["nzo-corp"])
        findings = _run_check(
            build_api_token_client(
                {token.id: token}, known_network_zone_ids={"nzo-corp"}
            )
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == token.id

    def test_token_open_to_anywhere_fails(self):
        token = api_token(network_connection="ANYWHERE", network_includes=[])
        findings = _run_check(build_api_token_client({token.id: token}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "from any IP" in findings[0].status_extended

    def test_token_restricted_to_unknown_zone_fails(self):
        token = api_token(network_connection="ZONE", network_includes=["nzo-missing"])
        findings = _run_check(
            build_api_token_client(
                {token.id: token}, known_network_zone_ids={"nzo-corp"}
            )
        )
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "unknown Network Zone" in findings[0].status_extended
