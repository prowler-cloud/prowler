from unittest import mock

import pytest

from prowler.providers.okta.exceptions.exceptions import (
    OktaEnvironmentVariableError,
    OktaInsufficientPermissionsError,
    OktaInvalidCredentialsError,
    OktaInvalidOrgDomainError,
    OktaInvalidProviderIdError,
    OktaPrivateKeyFileError,
    OktaSetUpIdentityError,
)
from prowler.providers.okta.models import OktaIdentityInfo, OktaSession
from prowler.providers.okta.okta_provider import DEFAULT_SCOPES, OktaProvider
from tests.providers.okta.okta_fixtures import (
    OKTA_CLIENT_ID,
    OKTA_ORG_DOMAIN,
    OKTA_PRIVATE_KEY,
)


@pytest.fixture
def _clear_okta_env(monkeypatch):
    for var in (
        "OKTA_ORG_DOMAIN",
        "OKTA_CLIENT_ID",
        "OKTA_PRIVATE_KEY",
        "OKTA_PRIVATE_KEY_FILE",
        "OKTA_SCOPES",
    ):
        monkeypatch.delenv(var, raising=False)


class Test_OktaProvider_validate_arguments:
    def test_missing_all_three_raises_combined(self, _clear_okta_env):
        with pytest.raises(OktaEnvironmentVariableError) as exc:
            OktaProvider.validate_arguments()
        msg = str(exc.value)
        assert "OKTA_ORG_DOMAIN" in msg
        assert "OKTA_CLIENT_ID" in msg
        assert "OKTA_PRIVATE_KEY" in msg

    def test_only_org_domain_missing(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        with pytest.raises(OktaEnvironmentVariableError) as exc:
            OktaProvider.validate_arguments(
                okta_client_id=OKTA_CLIENT_ID,
                okta_private_key_file=str(key_file),
            )
        assert "OKTA_ORG_DOMAIN" in str(exc.value)

    def test_accepts_private_key_content_in_place_of_file(self, _clear_okta_env):
        OktaProvider.validate_arguments(
            okta_org_domain=OKTA_ORG_DOMAIN,
            okta_client_id=OKTA_CLIENT_ID,
            okta_private_key=OKTA_PRIVATE_KEY,
        )

    def test_all_present_via_args(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        OktaProvider.validate_arguments(
            okta_org_domain=OKTA_ORG_DOMAIN,
            okta_client_id=OKTA_CLIENT_ID,
            okta_private_key_file=str(key_file),
        )

    def test_all_present_via_env(self, monkeypatch, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        monkeypatch.setenv("OKTA_ORG_DOMAIN", OKTA_ORG_DOMAIN)
        monkeypatch.setenv("OKTA_CLIENT_ID", OKTA_CLIENT_ID)
        monkeypatch.setenv("OKTA_PRIVATE_KEY_FILE", str(key_file))
        OktaProvider.validate_arguments()


class Test_OktaProvider_setup_session:
    def test_rejects_domain_with_scheme(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        with pytest.raises(OktaInvalidOrgDomainError):
            OktaProvider.setup_session(
                org_domain="https://acme.okta.com",
                client_id=OKTA_CLIENT_ID,
                private_key_file=str(key_file),
            )

    def test_rejects_domain_with_trailing_slash(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        with pytest.raises(OktaInvalidOrgDomainError):
            OktaProvider.setup_session(
                org_domain="acme.okta.com/",
                client_id=OKTA_CLIENT_ID,
                private_key_file=str(key_file),
            )

    def test_rejects_non_okta_tld(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        with pytest.raises(OktaInvalidOrgDomainError):
            OktaProvider.setup_session(
                org_domain="login.example.com",
                client_id=OKTA_CLIENT_ID,
                private_key_file=str(key_file),
            )

    def test_accepts_all_okta_managed_tlds(self, _clear_okta_env, tmp_path):
        # Mirrors the domain whitelist used by the Okta SDK
        # (okta.config.config_validator) so that gov/mil tenants — exactly the
        # audience most likely to care about the DISA STIG check — are not
        # turned away at provider init.
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        for domain in (
            "acme.oktapreview.com",
            "acme.okta-emea.com",
            "acme.okta-gov.com",
            "acme.okta.mil",
            "acme.okta-miltest.com",
            "acme.trex-govcloud.com",
        ):
            session = OktaProvider.setup_session(
                org_domain=domain,
                client_id=OKTA_CLIENT_ID,
                private_key_file=str(key_file),
            )
            assert session.org_domain == domain

    def test_unreadable_private_key_file_raises(self, _clear_okta_env):
        with pytest.raises(OktaPrivateKeyFileError):
            OktaProvider.setup_session(
                org_domain=OKTA_ORG_DOMAIN,
                client_id=OKTA_CLIENT_ID,
                private_key_file="/nonexistent/path.pem",
            )

    def test_happy_path_uses_default_scopes(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        session = OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            private_key_file=str(key_file),
        )
        assert session.org_domain == OKTA_ORG_DOMAIN
        assert session.client_id == OKTA_CLIENT_ID
        assert session.private_key == OKTA_PRIVATE_KEY
        assert session.scopes == DEFAULT_SCOPES

    def test_custom_scopes_parsed_from_csv(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        session = OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            private_key_file=str(key_file),
            scopes="okta.policies.read, okta.apps.read ,okta.users.read",
        )
        assert session.scopes == [
            "okta.policies.read",
            "okta.apps.read",
            "okta.users.read",
        ]

    def test_custom_scopes_accepts_list_input(self, _clear_okta_env, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        session = OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            private_key_file=str(key_file),
            scopes=["okta.policies.read", "okta.apps.read", "okta.users.read"],
        )
        assert session.scopes == [
            "okta.policies.read",
            "okta.apps.read",
            "okta.users.read",
        ]

    def test_custom_scopes_flattens_mixed_list_and_csv(self, _clear_okta_env, tmp_path):
        # Mirrors how argparse nargs="+" delivers values when a user
        # passes "--okta-scopes a,b c" — a list whose first element still
        # contains a comma.
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        session = OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            private_key_file=str(key_file),
            scopes=["okta.policies.read,okta.apps.read", "okta.users.read"],
        )
        assert session.scopes == [
            "okta.policies.read",
            "okta.apps.read",
            "okta.users.read",
        ]

    def test_org_domain_normalized_lowercase_and_trimmed(
        self, _clear_okta_env, tmp_path
    ):
        # The provider lowercases and strips whitespace so that
        # "  ACME.okta.com  " is accepted as "acme.okta.com".
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        session = OktaProvider.setup_session(
            org_domain="  ACME.okta.com  ",
            client_id=OKTA_CLIENT_ID,
            private_key_file=str(key_file),
        )
        assert session.org_domain == OKTA_ORG_DOMAIN

    def test_accepts_private_key_via_content_arg(self, _clear_okta_env):
        session = OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            private_key=OKTA_PRIVATE_KEY,
        )
        assert session.private_key == OKTA_PRIVATE_KEY

    def test_accepts_private_key_via_env_var(self, monkeypatch):
        monkeypatch.setenv("OKTA_PRIVATE_KEY", OKTA_PRIVATE_KEY)
        monkeypatch.delenv("OKTA_PRIVATE_KEY_FILE", raising=False)
        session = OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
        )
        assert session.private_key == OKTA_PRIVATE_KEY

    def test_content_takes_precedence_over_file(self, _clear_okta_env, tmp_path):
        # File has stale content; explicit content arg should win.
        key_file = tmp_path / "stale.pem"
        key_file.write_text("STALE CONTENT FROM FILE")
        fresh_key = "-----BEGIN PRIVATE KEY-----\nFRESH\n-----END PRIVATE KEY-----"
        session = OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            private_key=fresh_key,
            private_key_file=str(key_file),
        )
        assert session.private_key == fresh_key


class Test_OktaProvider_setup_identity:
    def _session(self, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text(OKTA_PRIVATE_KEY)
        return OktaProvider.setup_session(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            private_key_file=str(key_file),
        )

    def test_synthesizes_identity_and_probes_successfully(
        self, _clear_okta_env, tmp_path
    ):
        session = self._session(tmp_path)

        async def fake_list_policies(*_a, **_k):
            return ([], mock.MagicMock(headers={}), None)

        with mock.patch(
            "prowler.providers.okta.okta_provider.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked_client_cls.return_value = mocked
            identity = OktaProvider.setup_identity(session)

        assert identity.org_domain == OKTA_ORG_DOMAIN
        assert identity.client_id == OKTA_CLIENT_ID

    def test_raises_invalid_credentials_when_probe_returns_error(
        self, _clear_okta_env, tmp_path
    ):
        session = self._session(tmp_path)

        async def failing_list_policies(*_a, **_k):
            return ([], None, Exception("E0000011: Invalid token"))

        with mock.patch(
            "prowler.providers.okta.okta_provider.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = failing_list_policies
            mocked_client_cls.return_value = mocked
            with pytest.raises(OktaInvalidCredentialsError):
                OktaProvider.setup_identity(session)

    def test_raises_insufficient_permissions_on_scope_error(
        self, _clear_okta_env, tmp_path
    ):
        session = self._session(tmp_path)

        async def failing_list_policies(*_a, **_k):
            return ([], None, Exception("invalid_scope: policies.read missing"))

        with mock.patch(
            "prowler.providers.okta.okta_provider.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = failing_list_policies
            mocked_client_cls.return_value = mocked
            with pytest.raises(OktaInsufficientPermissionsError):
                OktaProvider.setup_identity(session)

    def test_raises_insufficient_permissions_on_forbidden(
        self, _clear_okta_env, tmp_path
    ):
        session = self._session(tmp_path)

        async def failing_list_policies(*_a, **_k):
            return ([], None, Exception("403 Forbidden"))

        with mock.patch(
            "prowler.providers.okta.okta_provider.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = failing_list_policies
            mocked_client_cls.return_value = mocked
            with pytest.raises(OktaInsufficientPermissionsError):
                OktaProvider.setup_identity(session)

    def test_wraps_unexpected_errors_in_setup_identity_error(
        self, _clear_okta_env, tmp_path
    ):
        session = self._session(tmp_path)

        async def boom(*_a, **_k):
            raise RuntimeError("network down")

        with mock.patch(
            "prowler.providers.okta.okta_provider.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = boom
            mocked_client_cls.return_value = mocked
            with pytest.raises(OktaSetUpIdentityError):
                OktaProvider.setup_identity(session)


def _mock_setup_paths():
    """Patches that bypass the real SDK during provider construction."""
    session = OktaSession(
        org_domain=OKTA_ORG_DOMAIN,
        client_id=OKTA_CLIENT_ID,
        scopes=list(DEFAULT_SCOPES),
        private_key=OKTA_PRIVATE_KEY,
    )
    identity = OktaIdentityInfo(org_domain=OKTA_ORG_DOMAIN, client_id=OKTA_CLIENT_ID)
    return (
        mock.patch.object(OktaProvider, "validate_arguments"),
        mock.patch.object(OktaProvider, "setup_session", return_value=session),
        mock.patch.object(OktaProvider, "setup_identity", return_value=identity),
    )


class Test_OktaProvider_init:
    def test_init_end_to_end(self, _clear_okta_env, tmp_path):
        validate_p, session_p, identity_p = _mock_setup_paths()
        with validate_p, session_p, identity_p:
            provider = OktaProvider(
                okta_org_domain=OKTA_ORG_DOMAIN,
                okta_client_id=OKTA_CLIENT_ID,
                okta_private_key_file="/tmp/key.pem",
            )

        assert provider.type == "okta"
        assert provider.auth_method == "OAuth 2.0 (private-key JWT)"
        assert provider.identity.org_domain == OKTA_ORG_DOMAIN
        assert provider.identity.client_id == OKTA_CLIENT_ID
        assert provider.session.scopes == DEFAULT_SCOPES
        assert provider.audit_config is not None
        assert provider.mutelist is not None


class Test_OktaProvider_test_connection:
    def test_success(self, _clear_okta_env, tmp_path):
        validate_p, session_p, identity_p = _mock_setup_paths()
        with validate_p, session_p, identity_p:
            connection = OktaProvider.test_connection(
                okta_org_domain=OKTA_ORG_DOMAIN,
                okta_client_id=OKTA_CLIENT_ID,
                okta_private_key_file="/tmp/key.pem",
            )
        assert connection.is_connected is True
        assert connection.error is None

    def test_returns_error_when_raise_disabled(self, _clear_okta_env):
        connection = OktaProvider.test_connection(raise_on_exception=False)
        assert connection.is_connected is False
        assert connection.error is not None

    def test_raises_when_raise_enabled(self, _clear_okta_env):
        with pytest.raises(OktaEnvironmentVariableError):
            OktaProvider.test_connection()

    def test_provider_id_match_succeeds(self, _clear_okta_env, tmp_path):
        validate_p, session_p, identity_p = _mock_setup_paths()
        with validate_p, session_p, identity_p:
            connection = OktaProvider.test_connection(
                okta_org_domain=OKTA_ORG_DOMAIN,
                okta_client_id=OKTA_CLIENT_ID,
                okta_private_key_file="/tmp/key.pem",
                provider_id=OKTA_ORG_DOMAIN,
            )
        assert connection.is_connected is True
        assert connection.error is None

    def test_provider_id_match_is_case_insensitive(self, _clear_okta_env, tmp_path):
        validate_p, session_p, identity_p = _mock_setup_paths()
        with validate_p, session_p, identity_p:
            connection = OktaProvider.test_connection(
                okta_org_domain=OKTA_ORG_DOMAIN,
                okta_client_id=OKTA_CLIENT_ID,
                okta_private_key_file="/tmp/key.pem",
                provider_id=OKTA_ORG_DOMAIN.upper(),
            )
        assert connection.is_connected is True

    def test_provider_id_mismatch_raises(self, _clear_okta_env, tmp_path):
        validate_p, session_p, identity_p = _mock_setup_paths()
        with validate_p, session_p, identity_p:
            with pytest.raises(OktaInvalidProviderIdError):
                OktaProvider.test_connection(
                    okta_org_domain=OKTA_ORG_DOMAIN,
                    okta_client_id=OKTA_CLIENT_ID,
                    okta_private_key_file="/tmp/key.pem",
                    provider_id="other.okta.com",
                )

    def test_provider_id_mismatch_returns_error_when_raise_disabled(
        self, _clear_okta_env, tmp_path
    ):
        validate_p, session_p, identity_p = _mock_setup_paths()
        with validate_p, session_p, identity_p:
            connection = OktaProvider.test_connection(
                okta_org_domain=OKTA_ORG_DOMAIN,
                okta_client_id=OKTA_CLIENT_ID,
                okta_private_key_file="/tmp/key.pem",
                provider_id="other.okta.com",
                raise_on_exception=False,
            )
        assert connection.is_connected is False
        assert isinstance(connection.error, OktaInvalidProviderIdError)


class Test_OktaProvider_print_credentials:
    def test_invokes_print_boxes_with_org_and_client(self, _clear_okta_env, tmp_path):
        validate_p, session_p, identity_p = _mock_setup_paths()
        with (
            validate_p,
            session_p,
            identity_p,
            mock.patch(
                "prowler.providers.okta.okta_provider.print_boxes"
            ) as mock_print,
        ):
            provider = OktaProvider(
                okta_org_domain=OKTA_ORG_DOMAIN,
                okta_client_id=OKTA_CLIENT_ID,
                okta_private_key_file="/tmp/key.pem",
            )
            provider.print_credentials()

        mock_print.assert_called_once()
        rendered = " ".join(mock_print.call_args.args[0])
        assert OKTA_ORG_DOMAIN in rendered
        assert OKTA_CLIENT_ID in rendered
        assert "OAuth 2.0" in rendered
