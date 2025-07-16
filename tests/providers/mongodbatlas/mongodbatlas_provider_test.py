from unittest.mock import MagicMock, patch

import pytest
import requests

from prowler.providers.mongodbatlas.exceptions.exceptions import (
    MongoDBAtlasAuthenticationError,
    MongoDBAtlasCredentialsError,
    MongoDBAtlasIdentityError,
)
from prowler.providers.mongodbatlas.models import (
    MongoDBAtlasIdentityInfo,
    MongoDBAtlasSession,
)
from prowler.providers.mongodbatlas.mongodbatlas_provider import MongodbatlasProvider
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ATLAS_BASE_URL,
    ATLAS_PRIVATE_KEY,
    ATLAS_PUBLIC_KEY,
    MOCK_ORGS_RESPONSE,
    USER_ID,
    USERNAME,
)


class TestMongodbatlasProvider:
    def test_mongodbatlas_provider_initialization(self):
        """Test MongoDB Atlas provider initialization"""
        with (
            patch(
                "prowler.providers.mongodbatlas.mongodbatlas_provider.MongodbatlasProvider.setup_session",
                return_value=MongoDBAtlasSession(
                    public_key=ATLAS_PUBLIC_KEY,
                    private_key=ATLAS_PRIVATE_KEY,
                    base_url=ATLAS_BASE_URL,
                ),
            ),
            patch(
                "prowler.providers.mongodbatlas.mongodbatlas_provider.MongodbatlasProvider.setup_identity",
                return_value=MongoDBAtlasIdentityInfo(
                    user_id=USER_ID,
                    username=USERNAME,
                    roles=["API_KEY"],
                ),
            ),
        ):
            provider = MongodbatlasProvider(
                atlas_public_key=ATLAS_PUBLIC_KEY,
                atlas_private_key=ATLAS_PRIVATE_KEY,
            )

            assert provider.type == "mongodbatlas"
            assert provider.session.public_key == ATLAS_PUBLIC_KEY
            assert provider.session.private_key == ATLAS_PRIVATE_KEY
            assert provider.identity.username == USERNAME

    def test_setup_session_with_credentials(self):
        """Test session setup with provided credentials"""
        session = MongodbatlasProvider.setup_session(
            atlas_public_key=ATLAS_PUBLIC_KEY,
            atlas_private_key=ATLAS_PRIVATE_KEY,
        )

        assert session.public_key == ATLAS_PUBLIC_KEY
        assert session.private_key == ATLAS_PRIVATE_KEY
        assert session.base_url == ATLAS_BASE_URL

    def test_setup_session_with_environment_variables(self):
        """Test session setup with environment variables"""
        with patch.dict(
            "os.environ",
            {
                "ATLAS_PUBLIC_KEY": ATLAS_PUBLIC_KEY,
                "ATLAS_PRIVATE_KEY": ATLAS_PRIVATE_KEY,
            },
        ):
            session = MongodbatlasProvider.setup_session()

            assert session.public_key == ATLAS_PUBLIC_KEY
            assert session.private_key == ATLAS_PRIVATE_KEY

    def test_setup_session_missing_credentials(self):
        """Test session setup with missing credentials"""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(MongoDBAtlasCredentialsError):
                MongodbatlasProvider.setup_session()

    @patch("requests.get")
    def test_setup_identity_success(self, mock_get):
        """Test successful identity setup"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = MOCK_ORGS_RESPONSE
        mock_get.return_value = mock_response

        session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )

        identity = MongodbatlasProvider.setup_identity(session)

        assert identity.user_id == USER_ID
        assert identity.username == USERNAME
        assert identity.roles == ["API_KEY"]

    @patch("requests.get")
    def test_setup_identity_authentication_error(self, mock_get):
        """Test identity setup with authentication error"""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "401 Unauthorized"
        )
        mock_get.return_value = mock_response

        session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )

        with pytest.raises(MongoDBAtlasAuthenticationError):
            MongodbatlasProvider.setup_identity(session)

    @patch("requests.get")
    def test_setup_identity_api_error(self, mock_get):
        """Test identity setup with API error"""
        mock_get.side_effect = requests.RequestException("Network error")

        session = MongoDBAtlasSession(
            public_key=ATLAS_PUBLIC_KEY,
            private_key=ATLAS_PRIVATE_KEY,
        )

        with pytest.raises(MongoDBAtlasIdentityError):
            MongodbatlasProvider.setup_identity(session)

    def test_test_connection_success(self):
        """Test successful connection test"""
        with (
            patch(
                "prowler.providers.mongodbatlas.mongodbatlas_provider.MongodbatlasProvider.setup_session",
                return_value=MongoDBAtlasSession(
                    public_key=ATLAS_PUBLIC_KEY,
                    private_key=ATLAS_PRIVATE_KEY,
                ),
            ),
            patch(
                "prowler.providers.mongodbatlas.mongodbatlas_provider.MongodbatlasProvider.setup_identity",
                return_value=MongoDBAtlasIdentityInfo(
                    user_id=USER_ID,
                    username=USERNAME,
                    roles=["API_KEY"],
                ),
            ),
        ):
            connection = MongodbatlasProvider.test_connection(
                atlas_public_key=ATLAS_PUBLIC_KEY,
                atlas_private_key=ATLAS_PRIVATE_KEY,
            )

            assert connection.is_connected is True

    def test_test_connection_failure(self):
        """Test failed connection test"""
        with (
            patch(
                "prowler.providers.mongodbatlas.mongodbatlas_provider.MongodbatlasProvider.setup_session",
                side_effect=MongoDBAtlasCredentialsError("Missing credentials"),
            ),
        ):
            connection = MongodbatlasProvider.test_connection(raise_on_exception=False)

            assert connection.is_connected is False
            assert connection.error is not None

    def test_provider_properties(self):
        """Test provider properties"""
        with (
            patch(
                "prowler.providers.mongodbatlas.mongodbatlas_provider.MongodbatlasProvider.setup_session",
                return_value=MongoDBAtlasSession(
                    public_key=ATLAS_PUBLIC_KEY,
                    private_key=ATLAS_PRIVATE_KEY,
                ),
            ),
            patch(
                "prowler.providers.mongodbatlas.mongodbatlas_provider.MongodbatlasProvider.setup_identity",
                return_value=MongoDBAtlasIdentityInfo(
                    user_id=USER_ID,
                    username=USERNAME,
                    roles=["API_KEY"],
                ),
            ),
        ):
            provider = MongodbatlasProvider(
                atlas_public_key=ATLAS_PUBLIC_KEY,
                atlas_private_key=ATLAS_PRIVATE_KEY,
                atlas_organization_id="test_org",
                atlas_project_id="test_project",
            )

            assert provider.type == "mongodbatlas"
            assert provider.organization_id == "test_org"
            assert provider.project_id == "test_project"
            assert provider.session.public_key == ATLAS_PUBLIC_KEY
            assert provider.identity.username == USERNAME
