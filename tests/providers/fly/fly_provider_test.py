from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.fly.exceptions.exceptions import (
    FlyAuthenticationError,
    FlyCredentialsError,
    FlyInvalidOrganizationError,
    FlyRateLimitError,
)
from prowler.providers.fly.fly_provider import FlyProvider
from prowler.providers.fly.models import FlySession
from tests.providers.fly.fly_fixtures import API_TOKEN, ORG_ID, ORG_NAME, ORG_SLUG

ORGANIZATIONS_PAYLOAD = {
    "data": {
        "organizations": {"nodes": [{"id": ORG_ID, "slug": ORG_SLUG, "name": ORG_NAME}]}
    }
}


def _session(org_slug: str = None, post_payload: dict = None) -> FlySession:
    http_session = MagicMock()
    post_response = MagicMock()
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
