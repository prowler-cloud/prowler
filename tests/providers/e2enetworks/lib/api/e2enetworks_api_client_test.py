from unittest.mock import MagicMock, patch

import pytest
import requests

from prowler.providers.e2enetworks.exceptions.exceptions import E2eNetworksAPIError
from prowler.providers.e2enetworks.lib.api.client import E2eNetworksAPIClient
from prowler.providers.e2enetworks.models import E2eNetworksSession


class TestE2eNetworksAPIClient:
    def test_get_redacts_api_key_from_errors(self):
        session = E2eNetworksSession(
            api_key="secret-api-key",
            auth_token="secret-auth-token",
            project_id=123,
            locations=["Delhi"],
            http_session=MagicMock(),
        )
        session.http_session.get.side_effect = requests.exceptions.HTTPError(
            "404 Client Error: Not Found for url: "
            "https://api.e2enetworks.com/myaccount/api/v1/nodes/"
            "?apikey=secret-api-key&project_id=123&location=Delhi "
            "Authorization: Bearer secret-auth-token"
        )

        client = E2eNetworksAPIClient(session)

        with patch(
            "prowler.providers.e2enetworks.lib.api.client.logger.error"
        ) as mock_logger:
            with pytest.raises(E2eNetworksAPIError) as error:
                client.get("/nodes/", location="Delhi")

        logged_message = mock_logger.call_args.args[0]
        assert "secret-api-key" not in logged_message
        assert "secret-auth-token" not in logged_message
        assert "apikey=REDACTED" in logged_message
        assert "Bearer REDACTED" in logged_message
        assert "secret-api-key" not in str(error.value)
        assert "secret-auth-token" not in str(error.value)
        assert "apikey=REDACTED" in str(error.value)
        assert "Bearer REDACTED" in str(error.value)
