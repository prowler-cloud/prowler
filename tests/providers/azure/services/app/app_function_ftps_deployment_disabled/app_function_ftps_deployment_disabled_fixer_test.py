from unittest import mock


class TestAppFunctionFtpsDeploymentDisabledFixer:
    def test_fix_success(self):
        regional_client = mock.MagicMock()
        app_client_mock = mock.MagicMock()
        app_client_mock.clients = {"subid": regional_client}
        regional_client.web_apps.update_configuration.return_value = None

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock.MagicMock(),
        ):
            with mock.patch(
                "prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled_fixer.app_client",
                new=app_client_mock,
            ):
                from prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled_fixer import (
                    AppFunctionFtpsDeploymentDisabledFixer,
                )

                fixer = AppFunctionFtpsDeploymentDisabledFixer()
                assert fixer.fix(
                    resource_group="rg1", resource_id="app1", subscription_id="subid"
                )
                regional_client.web_apps.update_configuration.assert_called_once()

    def test_fix_exception(self):
        regional_client = mock.MagicMock()
        app_client_mock = mock.MagicMock()
        app_client_mock.clients = {"subid": regional_client}
        regional_client.web_apps.update_configuration.side_effect = Exception("fail")

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock.MagicMock(),
        ):
            with mock.patch(
                "prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled_fixer.app_client",
                new=app_client_mock,
            ):
                from prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled_fixer import (
                    AppFunctionFtpsDeploymentDisabledFixer,
                )

                fixer = AppFunctionFtpsDeploymentDisabledFixer()
                assert not fixer.fix(
                    resource_group="rg1", resource_id="app1", subscription_id="subid"
                )
                regional_client.web_apps.update_configuration.assert_called_once()
