from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.defender.defender_service import (
    AutoProvisioningSetting,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_defender_auto_provisioning_log_analytics_agent_vms_on:
    def test_defender_no_app_services(self):
        defender_client = mock.MagicMock
        defender_client.auto_provisioning_settings = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
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
            AZURE_SUBSCRIPTION_ID: {
                "default": AutoProvisioningSetting(
                    resource_id=resource_id,
                    resource_name="default",
                    auto_provision="Off",
                    resource_type="Defender",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
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
                == f"Defender Auto Provisioning Log Analytics Agents from subscription {AZURE_SUBSCRIPTION_ID} is set to OFF."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_auto_provisioning_log_analytics_on(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.auto_provisioning_settings = {
            AZURE_SUBSCRIPTION_ID: {
                "default": AutoProvisioningSetting(
                    resource_id=resource_id,
                    resource_name="default",
                    auto_provision="On",
                    resource_type="Defender",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
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
                == f"Defender Auto Provisioning Log Analytics Agents from subscription {AZURE_SUBSCRIPTION_ID} is set to ON."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

    def test_defender_auto_provisioning_log_analytics_on_and_off(self):
        resource_id = str(uuid4())
        defender_client = mock.MagicMock
        defender_client.auto_provisioning_settings = {
            AZURE_SUBSCRIPTION_ID: {
                "default": AutoProvisioningSetting(
                    resource_id=resource_id,
                    resource_name="default",
                    auto_provision="On",
                    resource_type="Defender",
                ),
                "default2": AutoProvisioningSetting(
                    resource_id=resource_id,
                    resource_name="default2",
                    auto_provision="Off",
                    resource_type="Defender",
                ),
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on.defender_client",
            new=defender_client,
        ):
            from prowler.providers.azure.services.defender.defender_auto_provisioning_log_analytics_agent_vms_on.defender_auto_provisioning_log_analytics_agent_vms_on import (
                defender_auto_provisioning_log_analytics_agent_vms_on,
            )

            check = defender_auto_provisioning_log_analytics_agent_vms_on()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Defender Auto Provisioning Log Analytics Agents from subscription {AZURE_SUBSCRIPTION_ID} is set to ON."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "default"
            assert result[0].resource_id == resource_id

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == f"Defender Auto Provisioning Log Analytics Agents from subscription {AZURE_SUBSCRIPTION_ID} is set to OFF."
            )
            assert result[1].subscription == AZURE_SUBSCRIPTION_ID
            assert result[1].resource_name == "default2"
            assert result[1].resource_id == resource_id
