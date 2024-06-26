from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.policy.policy_service import PolicyAssigment
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_policy_ensure_asc_enforcement_enabled:
    def test_policy_no_subscriptions(self):
        policy_client = mock.MagicMock
        policy_client.policy_assigments = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled.policy_client",
            new=policy_client,
        ):
            from prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled import (
                policy_ensure_asc_enforcement_enabled,
            )

            check = policy_ensure_asc_enforcement_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_policy_subscription_empty(self):
        policy_client = mock.MagicMock
        policy_client.policy_assigments = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled.policy_client",
            new=policy_client,
        ):
            from prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled import (
                policy_ensure_asc_enforcement_enabled,
            )

            check = policy_ensure_asc_enforcement_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_policy_subscription_no_asc(self):
        policy_client = mock.MagicMock
        resource_id = uuid4()
        policy_client.policy_assigments = {
            AZURE_SUBSCRIPTION_ID: {
                "policy-1": PolicyAssigment(id=resource_id, enforcement_mode="Default")
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled.policy_client",
            new=policy_client,
        ):
            from prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled import (
                policy_ensure_asc_enforcement_enabled,
            )

            check = policy_ensure_asc_enforcement_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_policy_subscription_asc_default(self):
        policy_client = mock.MagicMock
        resource_id = uuid4()
        policy_client.policy_assigments = {
            AZURE_SUBSCRIPTION_ID: {
                "SecurityCenterBuiltIn": PolicyAssigment(
                    id=resource_id, enforcement_mode="Default"
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled.policy_client",
            new=policy_client,
        ):
            from prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled import (
                policy_ensure_asc_enforcement_enabled,
            )

            check = policy_ensure_asc_enforcement_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Policy assigment '{resource_id}' is configured with enforcement mode 'Default'."
            )
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "SecurityCenterBuiltIn"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_policy_subscription_asc_not_default(self):
        policy_client = mock.MagicMock
        resource_id = uuid4()
        policy_client.policy_assigments = {
            AZURE_SUBSCRIPTION_ID: {
                "SecurityCenterBuiltIn": PolicyAssigment(
                    id=resource_id,
                    enforcement_mode="DoNotEnforce",
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled.policy_client",
            new=policy_client,
        ):
            from prowler.providers.azure.services.policy.policy_ensure_asc_enforcement_enabled.policy_ensure_asc_enforcement_enabled import (
                policy_ensure_asc_enforcement_enabled,
            )

            check = policy_ensure_asc_enforcement_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Policy assigment '{resource_id}' is not configured with enforcement mode Default."
            )
            assert result[0].resource_id == resource_id
            assert result[0].resource_name == "SecurityCenterBuiltIn"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
