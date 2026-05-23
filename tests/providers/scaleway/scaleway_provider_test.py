import os
from unittest import mock

import pytest

from prowler.providers.scaleway.exceptions.exceptions import (
    ScalewayAuthenticationError,
    ScalewayCredentialsError,
    ScalewayIdentityError,
)
from prowler.providers.scaleway.models import ScalewaySession
from prowler.providers.scaleway.scaleway_provider import ScalewayProvider
from tests.providers.scaleway.scaleway_fixtures import (
    ACCESS_KEY,
    BEARER_EMAIL,
    ORGANIZATION_ID,
    ROOT_USER_ID,
    SECRET_KEY,
)


class Test_ScalewayProvider_setup_session:
    def test_missing_access_key_raises_credentials_error(self):
        with mock.patch.dict(
            os.environ, {"SCW_ACCESS_KEY": "", "SCW_SECRET_KEY": ""}, clear=False
        ):
            os.environ.pop("SCW_ACCESS_KEY", None)
            os.environ.pop("SCW_SECRET_KEY", None)
            with pytest.raises(ScalewayCredentialsError):
                ScalewayProvider.setup_session()

    def test_returns_session_with_credentials(self):
        session = ScalewayProvider.setup_session(
            access_key=ACCESS_KEY,
            secret_key=SECRET_KEY,
            organization_id=ORGANIZATION_ID,
        )
        assert isinstance(session, ScalewaySession)
        assert session.access_key == ACCESS_KEY
        assert session.organization_id == ORGANIZATION_ID
        assert session.default_region == "fr-par"


class Test_ScalewayProvider_setup_identity:
    def _build_session(self):
        return ScalewaySession(
            access_key=ACCESS_KEY,
            secret_key=SECRET_KEY,
            organization_id=ORGANIZATION_ID,
            default_region="fr-par",
            client=mock.MagicMock(),
        )

    def test_resolves_user_bearer_identity(self):
        session = self._build_session()
        api_key = mock.MagicMock(user_id=ROOT_USER_ID, application_id=None)
        user = mock.MagicMock(
            email=BEARER_EMAIL,
            organization_id=ORGANIZATION_ID,
            account_root_user_id=ROOT_USER_ID,
        )

        with mock.patch(
            "prowler.providers.scaleway.scaleway_provider.IamV1Alpha1API"
        ) as iam_cls:
            iam = iam_cls.return_value
            iam.get_api_key.return_value = api_key
            iam.get_user.return_value = user

            identity = ScalewayProvider.setup_identity(session)

        assert identity.organization_id == ORGANIZATION_ID
        assert identity.bearer_type == "user"
        assert identity.bearer_id == ROOT_USER_ID
        assert identity.bearer_email == BEARER_EMAIL
        assert identity.account_root_user_id == ROOT_USER_ID

    def test_missing_organization_raises_identity_error(self):
        session = self._build_session()
        session.organization_id = None
        api_key = mock.MagicMock(user_id=None, application_id="app-id")

        with mock.patch(
            "prowler.providers.scaleway.scaleway_provider.IamV1Alpha1API"
        ) as iam_cls:
            iam = iam_cls.return_value
            iam.get_api_key.return_value = api_key

            with pytest.raises(ScalewayIdentityError):
                ScalewayProvider.setup_identity(session)


class Test_ScalewayProvider_validate_credentials:
    def test_invalid_credentials_raise_authentication_error(self):
        session = ScalewaySession(
            access_key=ACCESS_KEY,
            secret_key=SECRET_KEY,
            organization_id=ORGANIZATION_ID,
            client=mock.MagicMock(),
        )
        with mock.patch(
            "prowler.providers.scaleway.scaleway_provider.IamV1Alpha1API"
        ) as iam_cls:
            iam_cls.return_value.get_api_key.side_effect = Exception("expired")
            with pytest.raises(ScalewayAuthenticationError):
                ScalewayProvider.validate_credentials(session)
