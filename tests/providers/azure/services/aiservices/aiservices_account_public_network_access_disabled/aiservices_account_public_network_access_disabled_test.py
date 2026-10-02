from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_account_public_network_access_disabled"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"


def build_account(public_network_access: bool) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="openai1",
        location="eastus",
        kind="OpenAI",
        public_network_access=public_network_access,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
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
        from prowler.providers.azure.services.aiservices.aiservices_account_public_network_access_disabled.aiservices_account_public_network_access_disabled import (
            aiservices_account_public_network_access_disabled,
        )

        return aiservices_account_public_network_access_disabled().execute()


class Test_aiservices_account_public_network_access_disabled:
    def test_no_accounts(self):
        assert run_check({}) == []

    def test_no_accounts_in_subscription(self):
        assert run_check({AZURE_SUBSCRIPTION_ID: {}}) == []

    def test_public_network_access_enabled(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(True)}})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY} has public network access enabled."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].location == "eastus"

    def test_public_network_access_disabled(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(False)}})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY} has public network access disabled."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
