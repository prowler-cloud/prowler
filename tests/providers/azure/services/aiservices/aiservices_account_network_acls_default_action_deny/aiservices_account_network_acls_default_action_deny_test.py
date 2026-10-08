from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_account_network_acls_default_action_deny"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"
PREFIX = f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY}"


def build_account(public_network_access: bool, default_action: str) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="openai1",
        location="eastus",
        kind="OpenAI",
        public_network_access=public_network_access,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
        network_acls_default_action=default_action,
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
        from prowler.providers.azure.services.aiservices.aiservices_account_network_acls_default_action_deny.aiservices_account_network_acls_default_action_deny import (
            aiservices_account_network_acls_default_action_deny,
        )

        return aiservices_account_network_acls_default_action_deny().execute()


class Test_aiservices_account_network_acls_default_action_deny:
    def test_no_resources(self):
        result = run_check({})
        assert len(result) == 0

    def test_public_access_from_all_networks(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(True, "Allow")}}
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{PREFIX} allows public network access from all networks."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_default_action_deny(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(True, "Deny")}}
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{PREFIX} restricts public network access to selected networks."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_public_network_access_disabled(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(False, "Allow")}}
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended == f"{PREFIX} has public network access disabled."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
