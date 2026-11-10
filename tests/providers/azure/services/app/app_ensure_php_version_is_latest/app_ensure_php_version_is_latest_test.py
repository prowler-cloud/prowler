from unittest import mock
from uuid import uuid4

import pytest

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK_PATH = "prowler.providers.azure.services.app.app_ensure_php_version_is_latest.app_ensure_php_version_is_latest"


def _run_check(app_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.app_client", new=app_client),
    ):
        from prowler.providers.azure.services.app.app_ensure_php_version_is_latest.app_ensure_php_version_is_latest import (
            app_ensure_php_version_is_latest,
        )

        return app_ensure_php_version_is_latest().execute()


def _app_client(configurations, audit_config=None):
    # app_service imports monitor_client, which needs the provider patched at import time
    with mock.patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=set_mocked_azure_provider(),
    ):
        from prowler.providers.azure.services.app.app_service import WebApp

    resource_id = f"/subscriptions/{uuid4()}"
    app_client = mock.MagicMock()
    app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    app_client.audit_config = audit_config or {}
    app_client.apps = {
        AZURE_SUBSCRIPTION_ID: {
            resource_id: WebApp(
                resource_id=resource_id,
                name="app_id-1",
                auth_enabled=True,
                configurations=configurations,
                client_cert_mode="Ignore",
                https_only=False,
                identity=None,
                location="West Europe",
            )
        }
    }
    return app_client, resource_id


class Test_app_ensure_php_version_is_latest:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock()
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        app_client.apps = {}
        assert len(_run_check(app_client)) == 0

    def test_app_subscription_empty(self):
        app_client = mock.MagicMock()
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        app_client.apps = {AZURE_SUBSCRIPTION_ID: {}}
        assert len(_run_check(app_client)) == 0

    def test_app_configurations_none(self):
        app_client, _ = _app_client(None)
        assert len(_run_check(app_client)) == 0

    def test_app_linux_fx_version_none_is_skipped(self):
        app_client, _ = _app_client(
            mock.MagicMock(linux_fx_version=None, php_version="")
        )
        assert len(_run_check(app_client)) == 0

    def test_app_linux_fx_version_none_uses_windows_version(self):
        app_client, _ = _app_client(
            mock.MagicMock(linux_fx_version=None, php_version="8.5")
        )
        result = _run_check(app_client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_app_other_runtime_is_skipped(self):
        app_client, _ = _app_client(
            mock.MagicMock(linux_fx_version="PYTHON|3.12", php_version="")
        )
        assert len(_run_check(app_client)) == 0

    @pytest.mark.parametrize(
        "configurations,minimum,expected_status,expected_message",
        [
            (
                {"linux_fx_version": "php|8.0", "php_version": ""},
                "8.2",
                "FAIL",
                "PHP version is set to 'php|8.0', which is below the minimum supported version '8.2',",
            ),
            (
                {"linux_fx_version": "PHP|8.1", "php_version": ""},
                "8.2",
                "FAIL",
                "PHP version is set to 'PHP|8.1', which is below the minimum supported version '8.2',",
            ),
            (
                {"linux_fx_version": "PHP|8.2", "php_version": ""},
                "8.2",
                "PASS",
                "PHP version is set to 'PHP|8.2', which meets the minimum supported version '8.2',",
            ),
            (
                {"linux_fx_version": "PHP|8.3", "php_version": ""},
                "8.2",
                "PASS",
                "PHP version is set to 'PHP|8.3', which meets the minimum supported version '8.2',",
            ),
            (
                {"linux_fx_version": "PHP|8.5", "php_version": ""},
                "8.2",
                "PASS",
                "PHP version is set to 'PHP|8.5', which meets the minimum supported version '8.2',",
            ),
            (
                {"linux_fx_version": "PHP|8.3", "php_version": ""},
                "8.4",
                "FAIL",
                "PHP version is set to 'PHP|8.3', which is below the minimum supported version '8.4',",
            ),
            (
                {"linux_fx_version": "PHP|8.2", "php_version": ""},
                "8.2.35",
                "PASS",
                "PHP version is set to 'PHP|8.2', which meets the minimum supported version '8.2.35',",
            ),
            (
                {"linux_fx_version": "", "php_version": "7.4"},
                "8.2",
                "FAIL",
                "PHP version is set to '7.4', which is below the minimum supported version '8.2',",
            ),
            (
                {"linux_fx_version": "", "php_version": "8.2"},
                "8.2",
                "PASS",
                "PHP version is set to '8.2', which meets the minimum supported version '8.2',",
            ),
            (
                {"linux_fx_version": "PHP|latest", "php_version": ""},
                "8.2",
                "FAIL",
                "PHP version is set to 'PHP|latest', which is below the minimum supported version '8.2',",
            ),
        ],
    )
    def test_app_php_version(
        self, configurations, minimum, expected_status, expected_message
    ):
        app_client, resource_id = _app_client(
            mock.MagicMock(**configurations), {"php_latest_version": minimum}
        )
        result = _run_check(app_client)
        assert len(result) == 1
        assert result[0].status == expected_status
        assert (
            result[0].status_extended
            == f"{expected_message} for app 'app_id-1' in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
        )
        assert result[0].resource_id == resource_id
        assert result[0].resource_name == "app_id-1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].location == "West Europe"

    def test_app_default_minimum(self):
        app_client, _ = _app_client(
            mock.MagicMock(linux_fx_version="PHP|8.5", php_version="")
        )
        result = _run_check(app_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
