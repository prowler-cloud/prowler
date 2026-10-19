from typing import Optional
from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_account_managed_identity_enabled"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"
PREFIX = f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY}"


def build_account(identity_type: Optional[str]) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="openai1",
        location="eastus",
        kind="OpenAI",
        public_network_access=False,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
        identity_type=identity_type,
    )


def run_check(accounts):
    aiservices_client = mock.MagicMock()
    aiservices_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    aiservices_client.accounts = accounts
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.aiservices_client", new=aiservices_client),
    ):
        from prowler.providers.azure.services.aiservices.aiservices_account_managed_identity_enabled.aiservices_account_managed_identity_enabled import (
            aiservices_account_managed_identity_enabled,
        )

        return aiservices_account_managed_identity_enabled().execute()


class Test_aiservices_account_managed_identity_enabled:
    def test_no_resources(self):
        result = run_check({})
        assert len(result) == 0

    def test_no_identity(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(None)}})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == f"{PREFIX} has no managed identity."
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_identity_type_none_string(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account("None")}})
        assert result[0].status == "FAIL"
        assert result[0].status_extended == f"{PREFIX} has no managed identity."

    def test_identity_type_none_string_lowercase(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account("none")}})
        assert result[0].status == "FAIL"

    def test_system_assigned_identity(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account("SystemAssigned")}}
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{PREFIX} has a managed identity (SystemAssigned)."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_system_and_user_assigned_identity(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    ACCOUNT_ID: build_account("SystemAssigned, UserAssigned")
                }
            }
        )
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{PREFIX} has a managed identity (SystemAssigned, UserAssigned)."
        )
