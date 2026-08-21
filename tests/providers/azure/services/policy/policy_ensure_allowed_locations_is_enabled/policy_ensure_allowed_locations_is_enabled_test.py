"""
Tests for policy_ensure_allowed_locations_is_enabled check.
"""

from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.policy.policy_service import PolicyAssigment
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_policy_ensure_allowed_locations_is_enabled:
    """Test suite for policy_ensure_allowed_locations_is_enabled."""

    def test_no_resources(self):
        """Test when policy_assigments has no subscriptions."""
        policy_client = mock.MagicMock()
        policy_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        policy_client.policy_assigments = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled.policy_client",
                new=policy_client,
            ),
        ):
            from prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled import (
                policy_ensure_allowed_locations_is_enabled,
            )

            check = policy_ensure_allowed_locations_is_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_assignments(self):
        """Test when no policy assignments exist in the subscription."""
        policy_client = mock.MagicMock()
        policy_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        policy_client.policy_assigments = {AZURE_SUBSCRIPTION_ID: {}}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled.policy_client",
                new=policy_client,
            ),
        ):
            from prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled import (
                policy_ensure_allowed_locations_is_enabled,
            )

            check = policy_ensure_allowed_locations_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Policy assignment for definition 'e56962a6-4747-49cd-b67b-bf8b01975c4c' does not exist or enforcement is disabled."
                in result[0].status_extended
            )

    def test_assignment_exists_and_enforced(self):
        """Test when policy assignment exists and is enforced."""
        policy_client = mock.MagicMock()
        policy_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        policy_client.policy_assigments = {
            AZURE_SUBSCRIPTION_ID: {
                "policy-1": PolicyAssigment(
                    id=str(uuid4()),
                    name="policy-1",
                    policy_definition_id="e56962a6-4747-49cd-b67b-bf8b01975c4c",
                    enforcement_mode="Default",
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled.policy_client",
                new=policy_client,
            ),
        ):
            from prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled import (
                policy_ensure_allowed_locations_is_enabled,
            )

            check = policy_ensure_allowed_locations_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "Policy assignment for definition 'e56962a6-4747-49cd-b67b-bf8b01975c4c' exists with enforcement enabled."
                in result[0].status_extended
            )

    def test_assignment_exists_not_enforced(self):
        """Test when policy assignment exists but enforcement is disabled."""
        policy_client = mock.MagicMock()
        policy_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        policy_client.policy_assigments = {
            AZURE_SUBSCRIPTION_ID: {
                "policy-1": PolicyAssigment(
                    id=str(uuid4()),
                    name="policy-1",
                    policy_definition_id="e56962a6-4747-49cd-b67b-bf8b01975c4c",
                    enforcement_mode="DoNotEnforce",
                )
            }
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled.policy_client",
                new=policy_client,
            ),
        ):
            from prowler.providers.azure.services.policy.policy_ensure_allowed_locations_is_enabled.policy_ensure_allowed_locations_is_enabled import (
                policy_ensure_allowed_locations_is_enabled,
            )

            check = policy_ensure_allowed_locations_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "Policy assignment for definition 'e56962a6-4747-49cd-b67b-bf8b01975c4c' does not exist or enforcement is disabled."
                in result[0].status_extended
            )
