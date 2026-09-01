from unittest import mock

from prowler.providers.fly.services.app.app_service import FlyApp, FlyIPAddress
from tests.providers.fly.fly_fixtures import (
    APP_ID,
    APP_NAME,
    ORG_SLUG,
    set_mocked_fly_provider,
)

PUBLIC_IP = FlyIPAddress(
    id="ip_test001", address="2001:db8::1", type="v6", region="global"
)


class Test_app_no_public_ip_address:
    def test_no_apps(self):
        app_client = mock.MagicMock
        app_client.apps = {}
        app_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(
                "prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address import (
                app_no_public_ip_address,
            )

            check = app_no_public_ip_address()
            result = check.execute()
            assert len(result) == 0

    def test_app_without_public_ip(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG)
        }
        app_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(
                "prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address import (
                app_no_public_ip_address,
            )

            check = app_no_public_ip_address()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"App {APP_NAME} has no public IP address allocated and is only "
                f"reachable over the private network."
            )
            assert result[0].resource_id == APP_ID
            assert result[0].resource_name == APP_NAME
            assert result[0].app_name == APP_NAME
            assert result[0].org_slug == ORG_SLUG

    def test_app_with_public_ip(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(
                id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG, public_ips=[PUBLIC_IP]
            )
        }
        app_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(
                "prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address import (
                app_no_public_ip_address,
            )

            check = app_no_public_ip_address()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"App {APP_NAME} is reachable from the internet through "
                f"{PUBLIC_IP.address} ({PUBLIC_IP.type})."
            )

    def test_approved_public_app(self):
        app_client = mock.MagicMock
        app_client.apps = {
            APP_NAME: FlyApp(
                id=APP_ID, name=APP_NAME, org_slug=ORG_SLUG, public_ips=[PUBLIC_IP]
            )
        }
        app_client.audit_config = {"public_apps": [APP_NAME]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_fly_provider(),
            ),
            mock.patch(
                "prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.fly.services.app.app_no_public_ip_address.app_no_public_ip_address import (
                app_no_public_ip_address,
            )

            check = app_no_public_ip_address()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"App {APP_NAME} is an approved public app and exposes "
                f"{PUBLIC_IP.address}."
            )
