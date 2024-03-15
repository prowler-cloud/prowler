from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.app.app_service import WebApp
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_app_register_with_identity:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock
        app_client.apps = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity import (
                app_register_with_identity,
            )

            check = app_register_with_identity()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscriptions_empty(self):
        app_client = mock.MagicMock
        app_client.apps = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity import (
                app_register_with_identity,
            )

            check = app_register_with_identity()
            result = check.execute()
            assert len(result) == 0

    def test_app_none_configurations(self):
        resource_id = f"/subscriptions/{uuid4()}"
        app_client = mock.MagicMock
        app_client.apps = {
            AZURE_SUBSCRIPTION: {
                "app_id-1": WebApp(
                    resource_id=resource_id,
                    auth_enabled=True,
                    configurations=None,
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
            "prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity import (
                app_register_with_identity,
            )

            check = app_register_with_identity()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"App 'app_id-1' in subscription '{AZURE_SUBSCRIPTION}' does not have an identity configured."
            )
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "app_id-1"
            assert result[0].subscription == AZURE_SUBSCRIPTION

    def test_app_identity(self):
        resource_id = f"/subscriptions/{uuid4()}"
        app_client = mock.MagicMock
        app_client.apps = {
            AZURE_SUBSCRIPTION: {
                "app_id-1": WebApp(
                    resource_id=resource_id,
                    auth_enabled=True,
                    configurations=None,
                    client_cert_mode="Ignore",
                    https_only=False,
                    identity=mock.MagicMock,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_register_with_identity.app_register_with_identity import (
                app_register_with_identity,
            )

            check = app_register_with_identity()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"App 'app_id-1' in subscription '{AZURE_SUBSCRIPTION}' has an identity configured."
            )
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "app_id-1"
            assert result[0].subscription == AZURE_SUBSCRIPTION
