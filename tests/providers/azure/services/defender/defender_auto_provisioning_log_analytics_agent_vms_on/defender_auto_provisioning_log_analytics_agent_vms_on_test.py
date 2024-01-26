from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import AutoProvisioningSetting

AZURE_SUSCRIPTION = str(uuid4())


class Test_defender_auto_provisioning_log_analytics_agent_vms_on:
    def test_defender_no_app_services(self):
        defender_client = mock.MagicMock
        defender_client.auto_provisioning_settings = {}

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on import (
                defender_auto_provisioning_log_analytics_agent_vms_on,
            )

            check = defender_auto_provisioning_log_analytics_agent_vms_on()
            result = check.execute()
            assert len(result) == 0

    def test_defender_auto_provisioning_log_analytics_off(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.auto_provisioning_settings = {
            AZURE_SUSCRIPTION: {
                "default": AutoProvisioningSetting(
                    resource_id=resource_id,
                    auto_provision="Off",
                    resource_type="Defender",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on import (
                defender_auto_provisioning_log_analytics_agent_vms_on,
            )

            check = defender_auto_provisioning_log_analytics_agent_vms_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defenter Auto Provisioning Log Analytics Agents from subscription {AZURE_SUSCRIPTION} is set to OFF."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "Defender Auto Provisioning Log Analytics Agents On"
            assert result[0].resource_id == resource_id

    def test_defender_auto_provisioning_log_analytics_on(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.auto_provisioning_settings = {
            AZURE_SUSCRIPTION: {
                "default": AutoProvisioningSetting(
                    resource_id=resource_id,
                    auto_provision="On",
                    resource_type="Defender",
                )
            }
        }

        with mock.patch(
            "prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on import (
                defender_auto_provisioning_log_analytics_agent_vms_on,
            )

            check = defender_auto_provisioning_log_analytics_agent_vms_on()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Defenter Auto Provisioning Log Analytics Agents from subscription {AZURE_SUSCRIPTION} is set to ON."
            )
            assert result[0].subscription == AZURE_SUSCRIPTION
            assert result[0].resource_name == "Defender Auto Provisioning Log Analytics Agents On"
            assert result[0].resource_id == resource_id