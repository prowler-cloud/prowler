from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defenderidentity_sensors_deployed:
    def test_sensors_none(self):
        """Test when sensors is None (API failed): expected FAIL."""
        defenderidentity_client = mock.MagicMock()
        defenderidentity_client.audited_tenant = "audited_tenant"
        defenderidentity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed.defenderidentity_client",
                new=defenderidentity_client,
            ),
        ):
            from prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed import (
                defenderidentity_sensors_deployed,
            )

            defenderidentity_client.sensors = None

            check = defenderidentity_sensors_deployed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Defender for Identity data is unavailable. Ensure the tenant is onboarded to Microsoft Defender for Identity and the required permissions are granted."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Defender for Identity"
            assert result[0].resource_id == "defenderIdentity"

    def test_no_sensors_deployed(self):
        """Test when no sensors are deployed (empty list): expected FAIL."""
        defenderidentity_client = mock.MagicMock()
        defenderidentity_client.audited_tenant = "audited_tenant"
        defenderidentity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed.defenderidentity_client",
                new=defenderidentity_client,
            ),
        ):
            from prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed import (
                defenderidentity_sensors_deployed,
            )

            defenderidentity_client.sensors = []

            check = defenderidentity_sensors_deployed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No Defender for Identity sensors are deployed. Deploy sensors on Domain Controllers to detect identity-based threats."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Defender for Identity"
            assert result[0].resource_id == "defenderIdentity"

    def test_sensor_healthy(self):
        """Test when sensor is deployed and healthy: expected PASS."""
        defenderidentity_client = mock.MagicMock()
        defenderidentity_client.audited_tenant = "audited_tenant"
        defenderidentity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed.defenderidentity_client",
                new=defenderidentity_client,
            ),
        ):
            from prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed import (
                defenderidentity_sensors_deployed,
            )
            from prowler.providers.m365.services.defenderidentity.defenderidentity_service import (
                Sensor,
            )

            sensor_id = "sensor-1"
            sensor_name = "DC01.example.com"

            defenderidentity_client.sensors = [
                Sensor(
                    id=sensor_id,
                    display_name=sensor_name,
                    sensor_type="domainControllerIntegrated",
                    deployment_status="upToDate",
                    health_status="healthy",
                    open_health_issues_count=0,
                    domain_name="example.com",
                    version="2.200.0.0",
                    created_date_time="2024-01-01T00:00:00Z",
                )
            ]

            check = defenderidentity_sensors_deployed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Defender for Identity sensor {sensor_name} is deployed and healthy."
            )
            assert result[0].resource_id == sensor_id
            assert result[0].resource_name == sensor_name

    def test_sensor_unhealthy(self):
        """Test when sensor is deployed but unhealthy: expected FAIL."""
        defenderidentity_client = mock.MagicMock()
        defenderidentity_client.audited_tenant = "audited_tenant"
        defenderidentity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed.defenderidentity_client",
                new=defenderidentity_client,
            ),
        ):
            from prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed import (
                defenderidentity_sensors_deployed,
            )
            from prowler.providers.m365.services.defenderidentity.defenderidentity_service import (
                Sensor,
            )

            sensor_id = "sensor-2"
            sensor_name = "DC02.example.com"

            defenderidentity_client.sensors = [
                Sensor(
                    id=sensor_id,
                    display_name=sensor_name,
                    sensor_type="domainControllerIntegrated",
                    deployment_status="upToDate",
                    health_status="notHealthyHigh",
                    open_health_issues_count=2,
                    domain_name="example.com",
                    version="2.200.0.0",
                    created_date_time="2024-01-01T00:00:00Z",
                )
            ]

            check = defenderidentity_sensors_deployed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender for Identity sensor {sensor_name} is deployed but has health status: notHealthyHigh."
            )
            assert result[0].resource_id == sensor_id
            assert result[0].resource_name == sensor_name

    def test_multiple_sensors_mixed_health(self):
        """Test when multiple sensors with different health statuses."""
        defenderidentity_client = mock.MagicMock()
        defenderidentity_client.audited_tenant = "audited_tenant"
        defenderidentity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed.defenderidentity_client",
                new=defenderidentity_client,
            ),
        ):
            from prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed import (
                defenderidentity_sensors_deployed,
            )
            from prowler.providers.m365.services.defenderidentity.defenderidentity_service import (
                Sensor,
            )

            defenderidentity_client.sensors = [
                Sensor(
                    id="sensor-1",
                    display_name="DC01.example.com",
                    sensor_type="domainControllerIntegrated",
                    deployment_status="upToDate",
                    health_status="healthy",
                    open_health_issues_count=0,
                    domain_name="example.com",
                    version="2.200.0.0",
                    created_date_time="2024-01-01T00:00:00Z",
                ),
                Sensor(
                    id="sensor-2",
                    display_name="DC02.example.com",
                    sensor_type="domainControllerIntegrated",
                    deployment_status="outdated",
                    health_status="notHealthyMedium",
                    open_health_issues_count=1,
                    domain_name="example.com",
                    version="2.199.0.0",
                    created_date_time="2024-01-01T00:00:00Z",
                ),
            ]

            check = defenderidentity_sensors_deployed()
            result = check.execute()

            assert len(result) == 2

            # First sensor is healthy
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sensor-1"
            assert (
                result[0].status_extended
                == "Defender for Identity sensor DC01.example.com is deployed and healthy."
            )

            # Second sensor is unhealthy
            assert result[1].status == "FAIL"
            assert result[1].resource_id == "sensor-2"
            assert (
                result[1].status_extended
                == "Defender for Identity sensor DC02.example.com is deployed but has health status: notHealthyMedium."
            )

    def test_sensor_unknown_health_status(self):
        """Test when sensor has unknown/None health status: expected FAIL."""
        defenderidentity_client = mock.MagicMock()
        defenderidentity_client.audited_tenant = "audited_tenant"
        defenderidentity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed.defenderidentity_client",
                new=defenderidentity_client,
            ),
        ):
            from prowler.providers.m365.services.defenderidentity.defenderidentity_sensors_deployed.defenderidentity_sensors_deployed import (
                defenderidentity_sensors_deployed,
            )
            from prowler.providers.m365.services.defenderidentity.defenderidentity_service import (
                Sensor,
            )

            sensor_id = "sensor-3"
            sensor_name = "DC03.example.com"

            defenderidentity_client.sensors = [
                Sensor(
                    id=sensor_id,
                    display_name=sensor_name,
                    sensor_type="domainControllerIntegrated",
                    deployment_status="upToDate",
                    health_status=None,
                    open_health_issues_count=0,
                    domain_name="example.com",
                    version="2.200.0.0",
                    created_date_time="2024-01-01T00:00:00Z",
                )
            ]

            check = defenderidentity_sensors_deployed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender for Identity sensor {sensor_name} is deployed but has health status: unknown."
            )
            assert result[0].resource_id == sensor_id
