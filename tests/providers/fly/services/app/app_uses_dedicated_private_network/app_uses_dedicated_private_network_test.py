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


def _run(app_client):
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

        return app_uses_dedicated_private_network().execute()


class Test_app_uses_dedicated_private_network:
    def test_no_apps(self):
        app_client = mock.MagicMock
        app_client.apps = {}

        assert len(_run(app_client)) == 0

    def test_dedicated_network(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(
                id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG, network="tenant-a"
            )
        }

        result = _run(app_client)
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

        result = _run(app_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"App {APP_NAME} runs on the shared organization network "
            f"'{SHARED_NETWORK}' and can reach every other app on it over 6PN."
        )

    def test_unknown_network_is_manual(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG)
        }

        result = _run(app_client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"App {APP_NAME} network assignment could not be determined because "
            f"the Fly.io API did not return its network; verify it manually with "
            f"'fly apps list' or the Machines API."
        )

    def test_empty_network_is_manual(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG, network=" ")
        }

        result = _run(app_client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
