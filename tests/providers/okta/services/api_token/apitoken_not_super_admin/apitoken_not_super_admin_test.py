from unittest import mock

import pytest

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.api_token.api_token_fixtures import (
    api_token,
    build_api_token_client,
)

CHECK_PATH = (
    "prowler.providers.okta.services.apitoken."
    "apitoken_not_super_admin.apitoken_not_super_admin.api_token_client"
)


def _run_check(api_token_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=api_token_client),
    ):
        from prowler.providers.okta.services.apitoken.apitoken_not_super_admin.apitoken_not_super_admin import (
            apitoken_not_super_admin,
        )

        return apitoken_not_super_admin().execute()


class Test_apitoken_not_super_admin:
    @pytest.mark.parametrize(
        "missing_scope", ["okta.apiTokens.read", "okta.roles.read"]
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

    def test_token_owner_without_super_admin_passes(self):
        token = api_token(owner_roles=["READ_ONLY_ADMIN"])
        findings = _run_check(build_api_token_client({token.id: token}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == token.id

    def test_token_owner_with_super_admin_fails(self):
        token = api_token(owner_roles=["SUPER_ADMIN"])
        findings = _run_check(build_api_token_client({token.id: token}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "Super Admin" in findings[0].status_extended
