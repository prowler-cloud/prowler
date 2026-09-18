from unittest.mock import MagicMock, patch

import pytest
import requests
import yaml

from prowler.providers.fly.exceptions.exceptions import (
    FlyAPIError,
    FlyAuthenticationError,
    FlyCredentialsError,
    FlyIdentityError,
    FlyInvalidArgumentError,
    FlyInvalidOrganizationError,
    FlyRateLimitError,
    FlySessionError,
)
from prowler.providers.fly.fly_provider import FlyProvider
from prowler.providers.fly.models import FlyIdentityInfo, FlyOrganization, FlySession
from tests.providers.fly.fly_fixtures import (
    API_TOKEN,
    APP_ID,
    APP_NAME,
    ORG_ID,
    ORG_NAME,
    ORG_SLUG,
)

ORGANIZATIONS_PAYLOAD = {
    "data": {
        "organizations": {"nodes": [{"id": ORG_ID, "slug": ORG_SLUG, "name": ORG_NAME}]}
    }
}
SECOND_ORG_ID = "org_test456"
SECOND_ORG_SLUG = "second-org"
MULTIPLE_ORGANIZATIONS_PAYLOAD = {
    "data": {
        "organizations": {
            "nodes": [
                {"id": ORG_ID, "slug": ORG_SLUG, "name": ORG_NAME},
                {"id": SECOND_ORG_ID, "slug": SECOND_ORG_SLUG, "name": "Second Org"},
            ]
        }
    }
}


def _session(
    org_slug: str = None, post_payload: dict = None, status_code: int = 200
) -> FlySession:
    http_session = MagicMock()
    post_response = MagicMock()
    post_response.status_code = status_code
    post_response.json.return_value = post_payload or ORGANIZATIONS_PAYLOAD
    http_session.post.return_value = post_response
    return FlySession(token=API_TOKEN, org_slug=org_slug, http_session=http_session)


class Test_FlyProvider:
    def test_setup_session_from_argument(self):
        session = FlyProvider.setup_session(api_token=API_TOKEN, organization=ORG_SLUG)
        assert session.token == API_TOKEN
        assert session.org_slug == ORG_SLUG

    def test_setup_session_from_environment(self):
        with patch.dict(
            "os.environ", {"FLY_API_TOKEN": API_TOKEN, "FLY_ORG": ORG_SLUG}
        ):
            session = FlyProvider.setup_session()
            assert session.token == API_TOKEN
            assert session.org_slug == ORG_SLUG

    def test_setup_session_without_token(self):
        with patch.dict("os.environ", {"FLY_API_TOKEN": ""}):
            with pytest.raises(FlyCredentialsError):
                FlyProvider.setup_session()

    def test_setup_identity_scoped_to_organization(self):
        identity = FlyProvider.setup_identity(_session(org_slug=ORG_SLUG))
        assert identity.organization.slug == ORG_SLUG
        assert identity.org_slugs == [ORG_SLUG]

    def test_setup_identity_single_organization_discovered(self):
        identity = FlyProvider.setup_identity(_session())
        assert identity.organization.slug == ORG_SLUG

    def test_setup_identity_unknown_organization(self):
        with pytest.raises(FlyInvalidOrganizationError):
            FlyProvider.setup_identity(_session(org_slug="another-org"))

    def test_validate_credentials(self):
        session = _session(org_slug=ORG_SLUG)
        session.http_session.get.return_value = MagicMock(status_code=200)
        FlyProvider.validate_credentials(session)
        session.http_session.get.assert_called_once()

    def test_validate_credentials_unauthorized(self):
        session = _session(org_slug=ORG_SLUG)
        session.http_session.get.return_value = MagicMock(status_code=401)
        with pytest.raises(FlyAuthenticationError):
            FlyProvider.validate_credentials(session)

    def test_validate_credentials_rate_limited(self):
        session = _session(org_slug=ORG_SLUG)
        session.http_session.get.return_value = MagicMock(status_code=429)
        with pytest.raises(FlyRateLimitError):
            FlyProvider.validate_credentials(session)

    def test_test_connection_without_raising(self):
        with patch.dict("os.environ", {"FLY_API_TOKEN": ""}):
            connection = FlyProvider.test_connection(raise_on_exception=False)
            assert connection.is_connected is False


class Test_FlyProvider_organizations:
    def test_multiple_organizations_without_slug_raise(self):
        with pytest.raises(FlyInvalidOrganizationError) as error:
            FlyProvider.setup_identity(
                _session(post_payload=MULTIPLE_ORGANIZATIONS_PAYLOAD)
            )

        message = str(error.value)
        assert "2 organizations" in message
        assert ORG_SLUG in message
        assert SECOND_ORG_SLUG in message
        assert "--organization" in message
        assert "FLY_ORG" in message

    def test_multiple_organizations_with_slug_select_one(self):
        identity = FlyProvider.setup_identity(
            _session(
                org_slug=SECOND_ORG_SLUG, post_payload=MULTIPLE_ORGANIZATIONS_PAYLOAD
            )
        )

        assert identity.organization.id == SECOND_ORG_ID
        assert identity.org_slugs == [SECOND_ORG_SLUG]
        assert [org.slug for org in identity.organizations] == [
            ORG_SLUG,
            SECOND_ORG_SLUG,
        ]

    def test_multiple_organizations_with_org_id_select_one(self):
        identity = FlyProvider.setup_identity(
            _session(
                org_slug=SECOND_ORG_ID, post_payload=MULTIPLE_ORGANIZATIONS_PAYLOAD
            )
        )

        assert identity.organization.slug == SECOND_ORG_SLUG

    def test_no_organizations_raise(self):
        with pytest.raises(FlyInvalidOrganizationError) as error:
            FlyProvider.setup_identity(
                _session(post_payload={"data": {"organizations": {"nodes": []}}})
            )

        assert "cannot read any organization" in str(error.value)

    def test_unauthorized_token_raises_authentication_error(self):
        with pytest.raises(FlyAuthenticationError):
            FlyProvider.setup_identity(_session(status_code=401))

    def test_forbidden_token_raises_authentication_error(self):
        with pytest.raises(FlyAuthenticationError):
            FlyProvider.setup_identity(_session(status_code=403))

    def test_rate_limited_lookup_raises_rate_limit_error(self):
        with pytest.raises(FlyRateLimitError):
            FlyProvider.setup_identity(_session(status_code=429))

    def test_graphql_errors_raise_identity_error(self):
        with pytest.raises(FlyIdentityError):
            FlyProvider.setup_identity(
                _session(post_payload={"errors": [{"message": "unauthorized"}]})
            )

    def test_test_connection_with_multiple_organizations_requires_selection(self):
        with patch.object(
            FlyProvider,
            "setup_session",
            return_value=_session(post_payload=MULTIPLE_ORGANIZATIONS_PAYLOAD),
        ):
            connection = FlyProvider.test_connection(
                api_token=API_TOKEN, raise_on_exception=False
            )

        assert connection.is_connected is False
        assert isinstance(connection.error, FlyInvalidOrganizationError)

    def test_validate_credentials_resolves_the_single_organization(self):
        session = _session()
        session.http_session.get.return_value = MagicMock(status_code=200)

        FlyProvider.validate_credentials(session)

        session.http_session.get.assert_called_once_with(
            f"{session.machines_base_url}/apps",
            params={"org_slug": ORG_SLUG},
            timeout=30,
        )

    def test_validate_credentials_uses_the_selected_organization(self):
        session = _session(
            org_slug=SECOND_ORG_SLUG, post_payload=MULTIPLE_ORGANIZATIONS_PAYLOAD
        )
        session.http_session.get.return_value = MagicMock(status_code=200)

        FlyProvider.validate_credentials(session)

        session.http_session.get.assert_called_once_with(
            f"{session.machines_base_url}/apps",
            params={"org_slug": SECOND_ORG_SLUG},
            timeout=30,
        )

    def test_validate_credentials_accepts_an_organization_id(self):
        session = _session(
            org_slug=SECOND_ORG_ID, post_payload=MULTIPLE_ORGANIZATIONS_PAYLOAD
        )
        session.http_session.get.return_value = MagicMock(status_code=200)

        FlyProvider.validate_credentials(session)

        session.http_session.get.assert_called_once_with(
            f"{session.machines_base_url}/apps",
            params={"org_slug": SECOND_ORG_SLUG},
            timeout=30,
        )

    def test_validate_credentials_rejects_an_unreadable_organization(self):
        session = _session(org_slug="another-org")

        with pytest.raises(FlyInvalidOrganizationError):
            FlyProvider.validate_credentials(session)

        session.http_session.get.assert_not_called()


class Test_FlyProvider_app_filter:
    def _provider(self, apps):
        organization = FlyOrganization(id=ORG_ID, slug=ORG_SLUG, name=ORG_NAME)
        identity = FlyIdentityInfo(
            organization=organization, organizations=[organization]
        )
        with (
            patch.object(
                FlyProvider, "setup_session", return_value=_session(org_slug=ORG_SLUG)
            ),
            patch.object(FlyProvider, "setup_identity", return_value=identity),
        ):
            return FlyProvider(
                api_token=API_TOKEN,
                organization=ORG_SLUG,
                apps=apps,
                config_content={},
                mutelist_content={},
            )

    def test_blank_app_names_are_dropped(self):
        provider = self._provider([" api ", "", "   ", "worker", None, 7, "api"])

        assert provider.filter_apps == {"api", "worker"}

    @pytest.mark.parametrize("apps", [[], ["", "  "], [None, 42]])
    def test_empty_app_selection_is_rejected_before_connecting(self, apps):
        """An explicit filter must not silently become an organization-wide scan."""
        with (
            patch.object(
                FlyProvider, "setup_session", return_value=_session(org_slug=ORG_SLUG)
            ) as setup_session,
            patch(
                "prowler.providers.fly.fly_provider.Provider.set_global_provider"
            ) as set_global_provider,
        ):
            with pytest.raises(
                FlyInvalidArgumentError, match="at least one non-empty app name"
            ) as error:
                FlyProvider(
                    apps=apps,
                    config_content={},
                    mutelist_content={},
                )

        assert error.value.code == 22007
        assert "omit" in error.value.remediation
        setup_session.assert_not_called()
        set_global_provider.assert_not_called()

    def test_no_apps_means_no_filter(self):
        provider = self._provider(None)

        assert provider.filter_apps is None
        assert provider.identity.organization.slug == ORG_SLUG


class Test_FlyProvider_mutelist:
    @pytest.mark.parametrize("explicit_path", [False, True])
    @pytest.mark.parametrize(
        "inline_content",
        [
            None,
            {},
            {
                "Accounts": {
                    ORG_SLUG: {
                        "Checks": {
                            "app_no_public_ip_address": {
                                "Regions": ["global"],
                                "Resources": ["inline-app-id"],
                            }
                        }
                    }
                }
            },
        ],
    )
    def test_inline_content_takes_precedence(
        self, tmp_path, explicit_path, inline_content
    ):
        """Only omitted inline content may load a default or explicit mutelist file."""
        file_content = {
            "Accounts": {
                ORG_SLUG: {
                    "Checks": {
                        "app_no_public_ip_address": {
                            "Regions": ["global"],
                            "Resources": [APP_ID],
                        }
                    }
                }
            }
        }
        mutelist_file = tmp_path / "fly-mutelist.yaml"
        mutelist_file.write_text(yaml.safe_dump({"Mutelist": file_content}))
        with (
            patch.object(FlyProvider, "setup_session", return_value=_session()),
            patch(
                "prowler.providers.fly.fly_provider.get_default_mute_file_path",
                return_value=str(mutelist_file),
            ) as default_path,
        ):
            provider = FlyProvider(
                config_content={},
                mutelist_path=str(mutelist_file) if explicit_path else None,
                mutelist_content=inline_content,
            )

        expected_content = file_content if inline_content is None else inline_content
        assert provider.mutelist.mutelist == expected_content
        assert provider.mutelist.mutelist_file_path == (
            str(mutelist_file) if inline_content is None else None
        )
        if inline_content is None and not explicit_path:
            default_path.assert_called_once_with("fly")
        else:
            default_path.assert_not_called()

        finding = MagicMock()
        finding.check_metadata.CheckID = "app_no_public_ip_address"
        finding.region = "global"
        finding.resource_id = APP_ID
        finding.resource_name = APP_NAME
        finding.resource_tags = []
        assert provider.mutelist.is_finding_muted(finding, ORG_SLUG) is (
            inline_content is None
        )
        finding.resource_id = "inline-app-id"
        assert provider.mutelist.is_finding_muted(finding, ORG_SLUG) is bool(
            inline_content
        )


class Test_FlyProvider_errors:
    @pytest.mark.parametrize(
        "status_code, expected_error",
        [
            (401, FlyAuthenticationError),
            (403, FlyAuthenticationError),
            (429, FlyRateLimitError),
            (404, FlyAPIError),
            (500, FlyAPIError),
            (503, FlyAPIError),
        ],
    )
    @pytest.mark.parametrize("boundary", ["validate", "raise", "return"])
    def test_http_error_classification(self, status_code, expected_error, boundary):
        """Real HTTP status handling must survive the connection-test wrapper."""
        session = _session(org_slug=ORG_SLUG)
        response = requests.Response()
        response.status_code = status_code
        response.url = f"{session.machines_base_url}/apps"
        session.http_session.get.return_value = response

        with patch.object(FlyProvider, "setup_session", return_value=session):
            if boundary == "return":
                connection = FlyProvider.test_connection(raise_on_exception=False)
                assert connection.is_connected is False
                error = connection.error
            else:
                with pytest.raises(expected_error) as raised:
                    if boundary == "validate":
                        FlyProvider.validate_credentials(session)
                    else:
                        FlyProvider.test_connection()
                error = raised.value

        assert isinstance(error, expected_error)
        if expected_error is FlyAPIError:
            assert isinstance(error.original_exception, requests.exceptions.HTTPError)
            assert error.original_exception.response is response
        session.http_session.get.assert_called_once()

    @pytest.mark.parametrize(
        "exception_type",
        [requests.exceptions.Timeout, requests.exceptions.ConnectionError],
    )
    @pytest.mark.parametrize("boundary", ["validate", "raise", "return"])
    def test_transport_failure_is_not_authentication_failure(
        self, exception_type, boundary
    ):
        """Network failures must not tell the user to replace a valid token."""
        session = _session(org_slug=ORG_SLUG)
        original = exception_type("Synthetic transport failure")
        session.http_session.get.side_effect = original

        with patch.object(FlyProvider, "setup_session", return_value=session):
            if boundary == "return":
                connection = FlyProvider.test_connection(raise_on_exception=False)
                assert connection.is_connected is False
                error = connection.error
            else:
                with pytest.raises(FlyAPIError) as raised:
                    if boundary == "validate":
                        FlyProvider.validate_credentials(session)
                    else:
                        FlyProvider.test_connection()
                error = raised.value

        assert isinstance(error, FlyAPIError)
        assert error.original_exception is original
        session.http_session.get.assert_called_once()

    @pytest.mark.parametrize(
        "exception_type",
        [
            FlyCredentialsError,
            FlySessionError,
            FlyAuthenticationError,
            FlyIdentityError,
            FlyInvalidOrganizationError,
            FlyRateLimitError,
            FlyAPIError,
        ],
    )
    @pytest.mark.parametrize("raise_on_exception", [False, True])
    def test_connection_preserves_provider_exceptions(
        self, exception_type, raise_on_exception
    ):
        """Known provider errors retain their original type and context."""
        original = exception_type()
        with (
            patch.object(FlyProvider, "setup_session", return_value=_session()),
            patch.object(FlyProvider, "validate_credentials", side_effect=original),
        ):
            if raise_on_exception:
                with pytest.raises(exception_type) as raised:
                    FlyProvider.test_connection()
                assert raised.value is original
            else:
                connection = FlyProvider.test_connection(raise_on_exception=False)
                assert connection.is_connected is False
                assert connection.error is original

    @pytest.mark.parametrize("raise_on_exception", [False, True])
    def test_connection_unexpected_failure_is_api_error(self, raise_on_exception):
        """Unexpected failures are reported, not reclassified as a bad token."""
        original = ValueError("Synthetic unexpected failure")
        with (
            patch.object(FlyProvider, "setup_session", return_value=_session()),
            patch.object(FlyProvider, "validate_credentials", side_effect=original),
        ):
            if raise_on_exception:
                with pytest.raises(FlyAPIError) as raised:
                    FlyProvider.test_connection()
                error = raised.value
            else:
                connection = FlyProvider.test_connection(raise_on_exception=False)
                assert connection.is_connected is False
                error = connection.error

        assert isinstance(error, FlyAPIError)
        assert error.original_exception is original
