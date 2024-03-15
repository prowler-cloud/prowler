from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.app.app_service import WebApp
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_app_ensure_http_is_redirected_to_https:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock
        app_client.apps = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                app_ensure_http_is_redirected_to_https,
            )

            check = app_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscriptions_empty_empty(self):
        app_client = mock.MagicMock
        app_client.apps = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                app_ensure_http_is_redirected_to_https,
            )

            check = app_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 0

    def test_app_http_to_https(self):
        resource_id = f"/subscriptions/{uuid4()}"
        app_client = mock.MagicMock
        app_client.apps = {
            AZURE_SUBSCRIPTION: {
                "app_id-1": WebApp(
                    resource_id=resource_id,
                    auth_enabled=True,
                    configurations=mock.MagicMock(),
                    client_cert_mode="Ignore",
                    https_only=False,
                    identity=None,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                app_ensure_http_is_redirected_to_https,
            )

            check = app_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"HTTP is not redirected to HTTPS for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].resource_name == "app_id-1"
            assert result[0].resource_id == resource_id
            assert result[0].subscription == AZURE_SUBSCRIPTION

    def test_app_http_to_https_enabled(self):
        resource_id = f"/subscriptions/{uuid4()}"
        app_client = mock.MagicMock
        app_client.apps = {
            AZURE_SUBSCRIPTION: {
                "app_id-1": WebApp(
                    resource_id=resource_id,
                    auth_enabled=True,
                    configurations=mock.MagicMock(),
                    client_cert_mode="Ignore",
                    https_only=True,
                    identity=None,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ensure_http_is_redirected_to_https.app_ensure_http_is_redirected_to_https import (
                app_ensure_http_is_redirected_to_https,
            )

            check = app_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"HTTP is redirected to HTTPS for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].resource_name == "app_id-1"
            assert result[0].resource_id == resource_id
            assert result[0].subscription == AZURE_SUBSCRIPTION
