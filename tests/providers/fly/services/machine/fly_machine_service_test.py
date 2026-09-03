from unittest import mock

from prowler.providers.fly.exceptions.exceptions import FlyAuthenticationError
from prowler.providers.fly.services.machine.machine_service import (
    FlyMachinePort,
    Machine,
)
from tests.providers.fly.fly_fixtures import (
    APP_NAME,
    MACHINE_ID,
    MACHINE_NAME,
    ORG_SLUG,
    REGION,
    set_mocked_fly_provider,
)

DIGEST = "sha256:" + "a" * 64

MACHINES_PAYLOAD = [
    {
        "id": MACHINE_ID,
        "name": MACHINE_NAME,
        "region": REGION,
        "state": "started",
        "image_ref": {
            "registry": "registry.fly.io",
            "repository": "test-app",
            "tag": "latest",
            "digest": DIGEST,
        },
        "config": {
            "image": "registry.fly.io/test-app:latest",
            "env": {"LOG_LEVEL": "info", "PORT": 8080},
            "services": [
                {
                    "protocol": "tcp",
                    "internal_port": 8080,
                    "ports": [
                        {"port": 80, "handlers": ["http"], "force_https": True},
                        {"port": 443, "handlers": ["tls", "http"]},
                        {"start_port": 9000, "end_port": 9010},
                    ],
                }
            ],
            "mounts": [
                {
                    "volume": "vol_test789",
                    "name": "data",
                    "path": "/data",
                    "size_gb": 10,
                    "encrypted": True,
                }
            ],
        },
    }
]

SECRETS_PAYLOAD = {"secrets": [{"name": "DATABASE_URL"}, {"name": "SESSION_SECRET"}]}


def _machine_service(get_side_effect) -> Machine:
    provider = set_mocked_fly_provider()
    with (
        mock.patch.object(Machine, "_app_scope", return_value=[(ORG_SLUG, APP_NAME)]),
        mock.patch.object(Machine, "_get", side_effect=get_side_effect),
    ):
        return Machine(provider)


class Test_FlyMachinePort:
    def test_single_port(self):
        assert FlyMachinePort(port=5432).published_ports() == {5432}

    def test_inclusive_range(self):
        assert FlyMachinePort(start_port=8000, end_port=8002).published_ports() == {
            8000,
            8001,
            8002,
        }

    def test_range_and_port_together(self):
        port = FlyMachinePort(port=80, start_port=9000, end_port=9001)

        assert port.published_ports() == {80, 9000, 9001}

    def test_reversed_range_is_normalised(self):
        assert FlyMachinePort(start_port=8002, end_port=8000).published_ports() == {
            8000,
            8001,
            8002,
        }

    def test_range_is_clamped_to_valid_ports(self):
        ports = FlyMachinePort(start_port=0, end_port=70000).published_ports()

        assert min(ports) == 1
        assert max(ports) == 65535

    def test_one_sided_range_extends_to_the_port_space_edge(self):
        # Mirrors the Fly.io client library: a missing bound means 1 or 65535.
        assert FlyMachinePort(start_port=65530).published_ports() == set(
            range(65530, 65536)
        )
        assert FlyMachinePort(end_port=3).published_ports() == {1, 2, 3}

    def test_empty_entry_publishes_nothing(self):
        assert FlyMachinePort().published_ports() == set()


class Test_Machine_service:
    def test_machines_are_parsed(self):
        service = _machine_service([MACHINES_PAYLOAD, SECRETS_PAYLOAD])

        machine = service.machines[f"{APP_NAME}/{MACHINE_ID}"]
        assert machine.name == MACHINE_NAME
        assert machine.app_name == APP_NAME
        assert machine.org_slug == ORG_SLUG
        assert machine.region == REGION
        assert machine.image == "registry.fly.io/test-app:latest"
        assert machine.image_digest == DIGEST
        assert machine.image_registry == "registry.fly.io"
        assert machine.image_repository == "test-app"
        assert machine.env == {"LOG_LEVEL": "info", "PORT": "8080"}
        assert machine.app_secret_names == ["DATABASE_URL", "SESSION_SECRET"]
        assert machine.mounts[0].volume == "vol_test789"
        assert machine.mounts[0].encrypted is True

    def test_port_ranges_are_parsed(self):
        service = _machine_service([MACHINES_PAYLOAD, SECRETS_PAYLOAD])

        ports = service.machines[f"{APP_NAME}/{MACHINE_ID}"].services[0].ports
        assert [port.port for port in ports] == [80, 443, None]
        assert ports[0].force_https is True
        assert ports[2].start_port == 9000
        assert ports[2].end_port == 9010
        assert ports[2].published_ports() == set(range(9000, 9011))

    def test_null_api_values_are_coerced(self):
        payload = [
            {
                "id": "nullmachine",
                "name": None,
                "region": None,
                "state": None,
                "image_ref": {"digest": None},
                "config": {
                    "image": None,
                    "env": {"PASSWORD": None, "PORT": 8080},
                    "services": [{"protocol": None, "ports": [{"port": None}]}],
                    "mounts": [{"volume": None, "size_gb": None}],
                },
            }
        ]
        service = _machine_service([payload, {"secrets": []}])

        machine = service.machines[f"{APP_NAME}/nullmachine"]
        assert machine.name == "nullmachine"
        assert machine.region == "global"
        assert machine.state == ""
        assert machine.image == ""
        assert machine.image_digest == ""
        assert machine.env == {"PASSWORD": "", "PORT": "8080"}
        assert machine.services[0].protocol == ""
        assert machine.services[0].ports[0].published_ports() == set()
        assert machine.mounts[0].volume == ""

    def test_missing_machines_are_skipped(self):
        service = _machine_service([None])

        assert service.machines == {}

    def test_secret_names_failure_is_logged(self):
        with mock.patch(
            "prowler.providers.fly.services.machine.machine_service.logger"
        ) as logger_mock:
            service = _machine_service([MACHINES_PAYLOAD, RuntimeError("boom")])

        machine = service.machines[f"{APP_NAME}/{MACHINE_ID}"]
        assert machine.app_secret_names is None
        logger_mock.error.assert_called_once()

    def test_secret_names_not_found_are_unknown(self):
        service = _machine_service([MACHINES_PAYLOAD, None])

        assert service.machines[f"{APP_NAME}/{MACHINE_ID}"].app_secret_names is None

    def test_forbidden_app_does_not_abort_other_apps(self):
        provider = set_mocked_fly_provider()
        with (
            mock.patch.object(
                Machine,
                "_app_scope",
                return_value=[(ORG_SLUG, "denied-app"), (ORG_SLUG, APP_NAME)],
            ),
            mock.patch.object(
                Machine,
                "_get",
                side_effect=[
                    FlyAuthenticationError(message="Access denied (403)"),
                    MACHINES_PAYLOAD,
                    SECRETS_PAYLOAD,
                ],
            ),
            mock.patch(
                "prowler.providers.fly.services.machine.machine_service.logger"
            ) as logger_mock,
        ):
            service = Machine(provider)

        assert list(service.machines) == [f"{APP_NAME}/{MACHINE_ID}"]
        logger_mock.error.assert_called_once()
        assert "denied-app" in logger_mock.error.call_args.args[0]
        assert "Access denied (403)" in logger_mock.error.call_args.args[0]

    def test_machine_listing_failure_is_logged(self):
        with mock.patch(
            "prowler.providers.fly.services.machine.machine_service.logger"
        ) as logger_mock:
            service = _machine_service([RuntimeError("boom")])

        assert service.machines == {}
        logger_mock.error.assert_called_once()
