from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.fly.exceptions.exceptions import (
    FlyAuthenticationError,
    FlyCredentialsError,
    FlyIdentityError,
    FlyInvalidOrganizationError,
    FlyRateLimitError,
)
from prowler.providers.fly.fly_provider import FlyProvider
from prowler.providers.fly.models import FlyIdentityInfo, FlyOrganization, FlySession
from tests.providers.fly.fly_fixtures import API_TOKEN, ORG_ID, ORG_NAME, ORG_SLUG

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
        provider = self._provider([" api ", "", "   ", "worker"])

        assert provider.filter_apps == {"api", "worker"}

    def test_only_blank_app_names_means_no_filter(self):
        provider = self._provider(["", "  "])

        assert provider.filter_apps is None

    def test_no_apps_means_no_filter(self):
        provider = self._provider(None)

        assert provider.filter_apps is None
        assert provider.identity.organization.slug == ORG_SLUG
