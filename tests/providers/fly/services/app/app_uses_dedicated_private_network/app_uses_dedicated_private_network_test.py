from unittest import mock

from prowler.providers.fly.services.app.app_service import SHARED_NETWORK, FlyApp
from tests.providers.fly.fly_fixtures import (
    APP_ID,
    APP_NAME,
    ORG_SLUG,
    set_mocked_fly_provider,
)

CHECK_MODULE = (
    "prowler.providers.fly.services.app.app_uses_dedicated_private_network."
    "app_uses_dedicated_private_network.app_client"
)


class Test_app_uses_dedicated_private_network:
    def test_no_apps(self):
        app_client = mock.MagicMock
        app_client.apps = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=app_client),
        ):
            from prowler.providers.fly.services.app.app_uses_dedicated_private_network.app_uses_dedicated_private_network import (
                app_uses_dedicated_private_network,
            )

            check = app_uses_dedicated_private_network()
            result = check.execute()
            assert len(result) == 0

    def test_dedicated_network(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(
                id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG, network="tenant-a"
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=app_client),
        ):
            from prowler.providers.fly.services.app.app_uses_dedicated_private_network.app_uses_dedicated_private_network import (
                app_uses_dedicated_private_network,
            )

            check = app_uses_dedicated_private_network()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"App {APP_NAME} runs on the dedicated private network tenant-a."
            )
            assert result[0].resource_id == APP_ID

    def test_shared_network(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(
                id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG, network=SHARED_NETWORK
            )
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(CHECK_MODULE, new=app_client),
        ):
            from prowler.providers.fly.services.app.app_uses_dedicated_private_network.app_uses_dedicated_private_network import (
                app_uses_dedicated_private_network,
            )

            check = app_uses_dedicated_private_network()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"App {APP_NAME} runs on the shared organization network "
                f"'{SHARED_NETWORK}' and can reach every other app on it over 6PN."
            )
