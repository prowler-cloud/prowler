from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_account_encrypted_with_cmk"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"


def build_account(key_source: str, key_name=None) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="openai1",
        location="eastus",
        kind="OpenAI",
        public_network_access=False,
        disable_local_auth=True,
        encryption_key_source=key_source,
        encryption_key_name=key_name,
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
        from prowler.providers.azure.services.aiservices.aiservices_account_encrypted_with_cmk.aiservices_account_encrypted_with_cmk import (
            aiservices_account_encrypted_with_cmk,
        )

        return aiservices_account_encrypted_with_cmk().execute()


class Test_aiservices_account_encrypted_with_cmk:
    def test_no_resources(self):
        result = run_check({})
        assert len(result) == 0

    def test_microsoft_managed_key(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    ACCOUNT_ID: build_account("Microsoft.CognitiveServices")
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY} is encrypted with a Microsoft-managed key."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_customer_managed_key(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    ACCOUNT_ID: build_account("Microsoft.KeyVault", "cmk1")
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY} is encrypted with customer-managed key cmk1."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_key_vault_source_without_key_name(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    ACCOUNT_ID: build_account("Microsoft.KeyVault", None)
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY} is encrypted with a customer-managed key from Azure Key Vault."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_key_vault_source_case_insensitive(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    ACCOUNT_ID: build_account("Microsoft.Keyvault", "cmk1")
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY} is encrypted with customer-managed key cmk1."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
