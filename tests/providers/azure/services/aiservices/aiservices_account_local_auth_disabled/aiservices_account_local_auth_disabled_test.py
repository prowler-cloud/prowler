from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_account_local_auth_disabled"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/foundry1"


def build_account(disable_local_auth: bool) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="foundry1",
        location="swedencentral",
        kind="AIServices",
        public_network_access=False,
        disable_local_auth=disable_local_auth,
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
        from prowler.providers.azure.services.aiservices.aiservices_account_local_auth_disabled.aiservices_account_local_auth_disabled import (
            aiservices_account_local_auth_disabled,
        )

        return aiservices_account_local_auth_disabled().execute()


class Test_aiservices_account_local_auth_disabled:
    def test_no_resources(self):
        result = run_check({})
        assert len(result) == 0

    def test_local_auth_enabled(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(False)}})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AI services account foundry1 (kind AIServices) from subscription {AZURE_SUBSCRIPTION_DISPLAY} allows local (API key) authentication."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "foundry1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_local_auth_disabled(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(True)}})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"AI services account foundry1 (kind AIServices) from subscription {AZURE_SUBSCRIPTION_DISPLAY} has local (API key) authentication disabled and requires Microsoft Entra ID."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "foundry1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
