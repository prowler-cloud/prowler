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


class Test_machine_no_public_non_http_ports:
    def test_no_machines(self):
        machine_client = mock.MagicMock
        machine_client.machines = {}
        machine_client.audit_config = {}

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

            check = machine_no_public_non_http_ports()
            result = check.execute()
            assert len(result) == 0

    def test_machine_without_published_ports(self):
        machine_client = mock.MagicMock
        machine_client.machines = {MACHINE_ID: _machine([])}
        machine_client.audit_config = {}

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

            check = machine_no_public_non_http_ports()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Machine {MACHINE_NAME} in app {APP_NAME} publishes no ports to the "
                f"Fly.io edge."
            )

    def test_machine_with_http_ports_only(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                [
                    FlyMachineService(
                        protocol="tcp",
                        internal_port=8080,
                        ports=[
                            FlyMachinePort(port=80, handlers=["http"]),
                            FlyMachinePort(port=443, handlers=["http", "tls"]),
                        ],
                    )
                ]
            )
        }
        machine_client.audit_config = {}

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

            check = machine_no_public_non_http_ports()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"Machine {MACHINE_NAME} in app {APP_NAME} publishes no edge ports "
                f"beyond 80, 443."
            )

    def test_machine_with_database_port(self):
        machine_client = mock.MagicMock
        machine_client.machines = {
            MACHINE_ID: _machine(
                [
                    FlyMachineService(
                        protocol="tcp",
                        internal_port=5432,
                        ports=[FlyMachinePort(port=5432)],
                    )
                ]
            )
        }
        machine_client.audit_config = {}

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

            check = machine_no_public_non_http_ports()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                f"Machine {MACHINE_NAME} in app {APP_NAME} publishes port(s) 5432 to "
                f"the Fly.io edge."
            )
