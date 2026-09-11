from unittest import mock

from prowler.providers.fly.exceptions.exceptions import FlyAPIError
from prowler.providers.fly.services.app.app_service import (
    SHARED_NETWORK,
    App,
    is_public_ip,
)
from tests.providers.fly.fly_fixtures import (
    APP_ID,
    APP_NAME,
    ORG_SLUG,
    set_mocked_fly_provider,
)

APPS_PAYLOAD = {
    "total_apps": 3,
    "apps": [
        {"id": APP_ID, "name": APP_NAME, "machine_count": 1, "network": "tenant-a"},
        {
            "id": "app_shared",
            "name": "shared-app",
            "machine_count": 1,
            "network": SHARED_NETWORK,
        },
        {"id": "app_unknown", "name": "unknown-app", "machine_count": 0},
    ],
}

IPS_PAYLOAD = {
    "organization": {
        "id": "org_test123",
        "slug": ORG_SLUG,
        "apps": {
            "nodes": [
                {
                    "name": APP_NAME,
                    "ipAddresses": {
                        "nodes": [
                            {
                                "id": "ip_test001",
                                "address": "2001:db8::1",
                                "type": "v6",
                                "region": "global",
                            }
                        ]
                    },
                },
                {"name": "shared-app", "ipAddresses": {"nodes": []}},
            ]
        },
    }
}

MIXED_IPS_PAYLOAD = {
    "organization": {
        "apps": {
            "nodes": [
                {
                    "name": APP_NAME,
                    "sharedIpAddress": "192.0.2.10",
                    "ipAddresses": {
                        "nodes": [
                            {
                                "id": "ip_private",
                                "address": "fdaa:0:1:0:1::2",
                                "type": "private_v6",
                                "region": "global",
                            },
                            {
                                "id": "ip_v6",
                                "address": "2001:db8::1",
                                "type": "v6",
                                "region": "global",
                            },
                        ]
                    },
                },
                {
                    "name": "shared-app",
                    "sharedIpAddress": "192.0.2.10",
                    "ipAddresses": {
                        "nodes": [
                            {
                                "id": "ip_shared",
                                "address": "192.0.2.10",
                                "type": "shared_v4",
                                "region": "global",
                            }
                        ]
                    },
                },
                {
                    "name": "unknown-app",
                    "sharedIpAddress": None,
                    "ipAddresses": {
                        "nodes": [
                            {
                                "id": "ip_flycast",
                                "address": "fdaa:0:1:0:1::3",
                                "type": "private_v6",
                                "region": "global",
                            }
                        ]
                    },
                },
            ]
        }
    }
}


def _app_service(get_side_effect, graphql_side_effect) -> App:
    provider = set_mocked_fly_provider()
    with (
        mock.patch.object(App, "_get", side_effect=get_side_effect),
        mock.patch.object(App, "_graphql", side_effect=graphql_side_effect),
    ):
        return App(provider)


class Test_App_service:
    def test_apps_are_listed_with_their_network(self):
        service = _app_service([APPS_PAYLOAD], [IPS_PAYLOAD])

        assert set(service.apps) == {APP_NAME, "shared-app", "unknown-app"}
        assert service.apps[APP_NAME].id == APP_ID
        assert service.apps[APP_NAME].org_slug == ORG_SLUG
        assert service.apps[APP_NAME].network == "tenant-a"
        assert service.apps["shared-app"].network == SHARED_NETWORK

    def test_missing_network_field_is_unknown(self):
        service = _app_service([APPS_PAYLOAD], [IPS_PAYLOAD])

        assert service.apps["unknown-app"].network is None

    def test_empty_network_field_is_unknown(self):
        payload = {"apps": [{"id": APP_ID, "name": APP_NAME, "network": ""}]}
        service = _app_service([payload], [{"organization": {"apps": {"nodes": []}}}])

        assert service.apps[APP_NAME].network is None

    def test_public_ips_are_attached(self):
        service = _app_service([APPS_PAYLOAD], [IPS_PAYLOAD])

        public_ips = service.apps[APP_NAME].public_ips
        assert len(public_ips) == 1
        assert public_ips[0].address == "2001:db8::1"
        assert public_ips[0].type == "v6"
        assert service.apps["shared-app"].public_ips == []

    def test_app_missing_from_ip_lookup_stays_unknown_and_is_logged(self):
        with mock.patch(
            "prowler.providers.fly.services.app.app_service.logger"
        ) as logger_mock:
            service = _app_service([APPS_PAYLOAD], [IPS_PAYLOAD])

        assert service.apps["unknown-app"].public_ips is None
        logger_mock.warning.assert_called_once()
        assert "unknown-app" in logger_mock.warning.call_args.args[0]

    def test_ip_lookup_follows_pagination(self):
        first_page = {
            "organization": {
                "apps": {
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                    "nodes": [{"name": APP_NAME, "ipAddresses": {"nodes": []}}],
                }
            }
        }
        second_page = {
            "organization": {
                "apps": {
                    "pageInfo": {"hasNextPage": False, "endCursor": "cursor-2"},
                    "nodes": [
                        {
                            "name": "shared-app",
                            "sharedIpAddress": "192.0.2.10",
                            "ipAddresses": {"nodes": []},
                        },
                        {"name": "unknown-app", "ipAddresses": {"nodes": []}},
                    ],
                }
            }
        }
        provider = set_mocked_fly_provider()
        with (
            mock.patch.object(App, "_get", side_effect=[APPS_PAYLOAD]),
            mock.patch.object(
                App, "_graphql", side_effect=[first_page, second_page]
            ) as graphql_mock,
        ):
            service = App(provider)

        assert graphql_mock.call_args_list[0].args[1] == {
            "slug": ORG_SLUG,
            "after": None,
        }
        assert graphql_mock.call_args_list[1].args[1] == {
            "slug": ORG_SLUG,
            "after": "cursor-1",
        }
        assert service.apps[APP_NAME].public_ips == []
        assert [ip.address for ip in service.apps["shared-app"].public_ips] == [
            "192.0.2.10"
        ]
        assert service.apps["unknown-app"].public_ips == []

    def test_ip_lookup_stops_on_repeated_cursor(self):
        page = {
            "organization": {
                "apps": {
                    "pageInfo": {"hasNextPage": True, "endCursor": "same"},
                    "nodes": [],
                }
            }
        }
        provider = set_mocked_fly_provider()
        with (
            mock.patch.object(App, "_get", side_effect=[APPS_PAYLOAD]),
            mock.patch.object(
                App, "_graphql", side_effect=[page, page, page]
            ) as graphql_mock,
        ):
            service = App(provider)

        assert graphql_mock.call_count == 2
        assert all(app.public_ips is None for app in service.apps.values())

    def test_failed_ip_lookup_leaves_public_ips_unknown(self):
        with mock.patch(
            "prowler.providers.fly.services.app.app_service.logger"
        ) as logger_mock:
            service = _app_service(
                [APPS_PAYLOAD], [FlyAPIError(message="GraphQL request failed")]
            )

        assert all(app.public_ips is None for app in service.apps.values())
        logger_mock.error.assert_called_once()
        assert ORG_SLUG in logger_mock.error.call_args.args[0]

    def test_app_filter_is_applied(self):
        provider = set_mocked_fly_provider()
        provider.filter_apps = {APP_NAME}
        with (
            mock.patch.object(App, "_get", side_effect=[APPS_PAYLOAD]),
            mock.patch.object(App, "_graphql", side_effect=[IPS_PAYLOAD]),
        ):
            service = App(provider)

        assert set(service.apps) == {APP_NAME}

    def test_unreadable_organization_is_logged(self):
        with mock.patch(
            "prowler.providers.fly.services.app.app_service.logger"
        ) as logger_mock:
            service = _app_service(
                [FlyAPIError(message="Access denied (403)")],
                [{"organization": {"apps": {"nodes": []}}}],
            )

        assert service.apps == {}
        logger_mock.error.assert_called_once()

    def test_get_app(self):
        service = _app_service([APPS_PAYLOAD], [IPS_PAYLOAD])

        assert service.get_app(APP_NAME).name == APP_NAME
        assert service.get_app("missing") is None


class Test_App_service_public_ips:
    def test_private_flycast_addresses_are_not_public(self):
        service = _app_service([APPS_PAYLOAD], [MIXED_IPS_PAYLOAD])

        assert service.apps["unknown-app"].public_ips == []

    def test_dedicated_and_shared_addresses_are_public(self):
        service = _app_service([APPS_PAYLOAD], [MIXED_IPS_PAYLOAD])

        addresses = [(ip.address, ip.type) for ip in service.apps[APP_NAME].public_ips]
        assert addresses == [("2001:db8::1", "v6"), ("192.0.2.10", "shared_v4")]

    def test_shared_ipv4_is_not_duplicated(self):
        service = _app_service([APPS_PAYLOAD], [MIXED_IPS_PAYLOAD])

        addresses = [ip.address for ip in service.apps["shared-app"].public_ips]
        assert addresses == ["192.0.2.10"]


class Test_is_public_ip:
    def test_public_types(self):
        assert is_public_ip({"address": "192.0.2.1", "type": "v4"})
        assert is_public_ip({"address": "192.0.2.1", "type": "shared_v4"})
        assert is_public_ip({"address": "2001:db8::1", "type": "v6"})
        assert is_public_ip({"address": "2001:db8::1", "type": ""})

    def test_private_addresses(self):
        assert not is_public_ip({"address": "fdaa:0:1::2", "type": "private_v6"})
        assert not is_public_ip({"address": "FDAA:0:1::2", "type": "v6"})
        assert not is_public_ip({"address": "2001:db8::1", "type": "PRIVATE_V6"})
        assert not is_public_ip({"address": "", "type": "v4"})
        assert not is_public_ip({"type": "v4"})
