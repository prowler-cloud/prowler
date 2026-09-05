from unittest import mock

from prowler.providers.fly.services.machine.machine_service import (
    FlyMachine,
    FlyMachinePort,
    FlyMachineService,
)
from tests.providers.fly.fly_fixtures import (
    APP_NAME,
    MACHINE_ID,
    MACHINE_NAME,
    ORG_SLUG,
    REGION,
    set_mocked_fly_provider,
)

CHECK_MODULE = (
    "prowler.providers.fly.services.machine.machine_no_public_non_http_ports."
    "machine_no_public_non_http_ports.machine_client"
)


def _machine(services: list) -> FlyMachine:
    return FlyMachine(
        id=MACHINE_ID,
        name=MACHINE_NAME,
        app_name=APP_NAME,
        org_slug=ORG_SLUG,
        region=REGION,
        state="started",
        image="registry.fly.io/test-app@sha256:" + "a" * 64,
        services=services,
    )


def _service(*ports: FlyMachinePort) -> FlyMachineService:
    return FlyMachineService(protocol="tcp", internal_port=8080, ports=list(ports))


def _run(machine_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_fly_provider(),
        ),
        mock.patch(CHECK_MODULE, new=machine_client),
    ):
        from prowler.providers.fly.services.machine.machine_no_public_non_http_ports.machine_no_public_non_http_ports import (
            machine_no_public_non_http_ports,
        )

        return machine_no_public_non_http_ports().execute()


class Test_format_ports:
    def test_runs_are_collapsed(self):
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_fly_provider(),
        ):
            from prowler.providers.fly.services.machine.machine_no_public_non_http_ports.machine_no_public_non_http_ports import (
                format_ports,
            )

        assert format_ports({5432}) == "5432"
        assert format_ports({80, 443}) == "80, 443"
        assert format_ports({8000, 8001, 8002, 8443}) == "8000-8002, 8443"
        assert format_ports(set()) == ""


class Test_machine_no_public_non_http_ports:
    def test_no_machines(self):
        machine_client = mock.MagicMock
        machine_client.machines = {}
        machine_client.audit_config = {}

        assert len(_run(machine_client)) == 0

    def test_machine_without_published_ports(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine([])}
        machine_client.audit_config = {}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} publishes no ports to the "
            f"Fly.io edge."
        )
        assert result[0].resource_id == MACHINE_ID
        assert result[0].region == REGION

    def test_machine_with_http_ports_only(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                [
                    _service(
                        FlyMachinePort(port=80, handlers=["http"]),
                        FlyMachinePort(port=443, handlers=["http", "tls"]),
                    )
                ]
            )
        }
        machine_client.audit_config = {}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} publishes no edge ports "
            f"beyond 80, 443."
        )

    def test_machine_with_database_port(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine([_service(FlyMachinePort(port=5432))])
        }
        machine_client.audit_config = {}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} publishes port(s) 5432 to "
            f"the Fly.io edge."
        )

    def test_machine_with_port_range(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                [_service(FlyMachinePort(start_port=8000, end_port=8010))]
            )
        }
        machine_client.audit_config = {}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} publishes port(s) "
            f"8000-8010 to the Fly.io edge."
        )

    def test_machine_with_range_and_single_ports(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                [
                    _service(FlyMachinePort(port=443, handlers=["tls", "http"])),
                    _service(
                        FlyMachinePort(port=5432),
                        FlyMachinePort(start_port=5000, end_port=5002),
                    ),
                ]
            )
        }
        machine_client.audit_config = {}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            f"Machine {MACHINE_NAME} in app {APP_NAME} publishes port(s) "
            f"5000-5002, 5432 to the Fly.io edge."
        )

    def test_range_inside_the_allow_list_passes(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine([_service(FlyMachinePort(start_port=80, end_port=80))])
        }
        machine_client.audit_config = {}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_range_spilling_over_the_allow_list_fails(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine([_service(FlyMachinePort(start_port=80, end_port=81))])
        }
        machine_client.audit_config = {}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended.endswith(
            "publishes port(s) 81 to the Fly.io edge."
        )

    def test_custom_allowed_ports(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine([_service(FlyMachinePort(port=5432))])
        }
        machine_client.audit_config = {"allowed_public_ports": [80, 443, 5432]}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended.endswith("beyond 80, 443, 5432.")

    def test_null_allowed_ports_config_uses_default(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine([_service(FlyMachinePort(port=443))])
        }
        machine_client.audit_config = {"allowed_public_ports": None}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_empty_allowed_ports_config_flags_every_port(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine([_service(FlyMachinePort(port=443))])
        }
        machine_client.audit_config = {"allowed_public_ports": []}

        result = _run(machine_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended.endswith(
            "publishes port(s) 443 to the Fly.io edge."
        )
