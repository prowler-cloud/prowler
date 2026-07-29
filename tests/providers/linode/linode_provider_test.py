import os
from unittest import mock

import pytest

from prowler.providers.linode.exceptions.exceptions import (
    LinodeAuthenticationError,
    LinodeCredentialsError,
    LinodeInvalidRegionError,
)
from prowler.providers.linode.linode_provider import LinodeProvider
from prowler.providers.linode.models import LinodeIdentityInfo, LinodeSession
from tests.providers.linode.linode_fixtures import (
    ACCOUNT_ID,
    EMAIL,
    TOKEN,
    USERNAME,
)


class TestLinodeProvider_setup_session:
    def test_missing_token_raises_credentials_error(self):
        with mock.patch.dict(os.environ, {"LINODE_TOKEN": ""}, clear=False):
            os.environ.pop("LINODE_TOKEN", None)
            with pytest.raises(LinodeCredentialsError):
                LinodeProvider.setup_session()

    def test_returns_session_with_token(self):
        session = LinodeProvider.setup_session(token=TOKEN)
        assert isinstance(session, LinodeSession)
        assert session.token == TOKEN
        assert session.client is not None

    def test_reads_token_from_env(self):
        with mock.patch.dict(os.environ, {"LINODE_TOKEN": TOKEN}, clear=False):
            session = LinodeProvider.setup_session()
            assert session.token == TOKEN


class TestLinodeProvider_setup_identity:
    def _build_session(self):
        client = mock.MagicMock()
        return LinodeSession(client=client, token=TOKEN)

    def test_resolves_identity_from_profile_and_account(self):
        session = self._build_session()
        profile = mock.MagicMock()
        profile.username = USERNAME
        profile.email = EMAIL
        session.client.profile.return_value = profile

        account = mock.MagicMock()
        account.euuid = ACCOUNT_ID
        session.client.account.return_value = account

        identity = LinodeProvider.setup_identity(session)

        assert isinstance(identity, LinodeIdentityInfo)
        assert identity.username == USERNAME
        assert identity.email == EMAIL
        assert identity.account_id == ACCOUNT_ID

    def test_invalid_token_raises_authentication_error(self):
        # An invalid token fails the profile call (any valid token can read its
        # own profile), so the scan must abort instead of returning empty data.
        session = self._build_session()
        session.client.profile.side_effect = Exception("[401] Invalid Token")

        with pytest.raises(LinodeAuthenticationError):
            LinodeProvider.setup_identity(session)

    def test_identity_with_account_failure_still_returns(self):
        session = self._build_session()
        profile = mock.MagicMock()
        profile.username = USERNAME
        profile.email = EMAIL
        session.client.profile.return_value = profile
        session.client.account.side_effect = Exception("forbidden")

        identity = LinodeProvider.setup_identity(session)

        assert identity.username == USERNAME
        assert identity.email == EMAIL
        assert identity.account_id is None


class TestLinodeProvider_test_connection:
    def test_successful_connection(self):
        with mock.patch(
            "prowler.providers.linode.linode_provider.LinodeProvider.setup_session"
        ) as mock_session:
            session = mock.MagicMock()
            session.client.profile.return_value = mock.MagicMock()
            mock_session.return_value = session

            conn = LinodeProvider.test_connection(token=TOKEN, raise_on_exception=False)

            assert conn.is_connected is True

    def test_missing_credentials(self):
        with mock.patch.dict(os.environ, {"LINODE_TOKEN": ""}, clear=False):
            os.environ.pop("LINODE_TOKEN", None)
            conn = LinodeProvider.test_connection(token=None, raise_on_exception=False)
            assert conn.is_connected is False

    def test_connection_failure_raises_when_requested(self):
        with mock.patch(
            "prowler.providers.linode.linode_provider.LinodeProvider.setup_session"
        ) as mock_session:
            mock_session.side_effect = LinodeCredentialsError(
                file="test", message="No token"
            )
            with pytest.raises(LinodeCredentialsError):
                LinodeProvider.test_connection(token=None, raise_on_exception=True)


class TestLinodeProvider_validate_regions:
    def _session_with_regions(self, region_ids):
        client = mock.MagicMock()
        client.regions.return_value = [mock.MagicMock(id=rid) for rid in region_ids]
        return LinodeSession(client=client, token=TOKEN)

    def test_no_regions_returns_none(self):
        session = self._session_with_regions(["eu-central", "us-east"])
        assert LinodeProvider.validate_regions(session, None) is None

    def test_valid_regions_returns_set(self):
        session = self._session_with_regions(["eu-central", "us-east", "ap-south"])
        result = LinodeProvider.validate_regions(session, ["eu-central", "us-east"])
        assert result == {"eu-central", "us-east"}

    def test_invalid_region_raises(self):
        session = self._session_with_regions(["eu-central", "us-east"])
        with pytest.raises(LinodeInvalidRegionError):
            LinodeProvider.validate_regions(session, ["eu-central", "nonexistent"])

    def test_regions_api_failure_does_not_block(self):
        # If the public regions list cannot be fetched, the scan proceeds with
        # the requested regions instead of failing.
        client = mock.MagicMock()
        client.regions.side_effect = Exception("regions API error")
        session = LinodeSession(client=client, token=TOKEN)

        result = LinodeProvider.validate_regions(session, ["eu-central"])

        assert result == {"eu-central"}
