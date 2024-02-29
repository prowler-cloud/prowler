from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.app.app_service import WebApp
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_app_ftp_deployment_disabled:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock
        app_client.apps = {}

        with mock.patch(
            "prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled import (
                app_ftp_deployment_disabled,
            )

            check = app_ftp_deployment_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscriptions_empty(self):
        app_client = mock.MagicMock
        app_client.apps = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled import (
                app_ftp_deployment_disabled,
            )

            check = app_ftp_deployment_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_app_configurations_none(self):
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
            "prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled import (
                app_ftp_deployment_disabled,
            )

            check = app_ftp_deployment_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"FTP is enabled for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "app_id-1"
            assert result[0].subscription == AZURE_SUBSCRIPTION

    def test_app_ftp_deployment_disabled(self):
        resource_id = f"/subscriptions/{uuid4()}"
        app_client = mock.MagicMock
        app_client.apps = {
            AZURE_SUBSCRIPTION: {
                "app_id-1": WebApp(
                    resource_id=resource_id,
                    auth_enabled=True,
                    configurations=mock.MagicMock(ftps_state="AllAllowed"),
                    client_cert_mode="Ignore",
                    https_only=False,
                    identity=None,
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled import (
                app_ftp_deployment_disabled,
            )

            check = app_ftp_deployment_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"FTP is enabled for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "app_id-1"
            assert result[0].subscription == AZURE_SUBSCRIPTION

    def test_app_ftp_deploy_enabled(self):
        resource_id = f"/subscriptions/{uuid4()}"
        app_client = mock.MagicMock
        app_client.apps = {
            AZURE_SUBSCRIPTION: {
                "app_id-1": WebApp(
                    resource_id=resource_id,
                    auth_enabled=True,
                    configurations=mock.MagicMock(ftps_state="Disabled"),
                    client_cert_mode="Ignore",
                    https_only=False,
                    identity=None,
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_ftp_deployment_disabled.app_ftp_deployment_disabled import (
                app_ftp_deployment_disabled,
            )

            check = app_ftp_deployment_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"FTP is disabled for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "app_id-1"
            assert result[0].subscription == AZURE_SUBSCRIPTION
