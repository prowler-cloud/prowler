from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import Account
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_account_uses_private_endpoint"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"
PREFIX = f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY}"


def build_account(statuses: list[str]) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="openai1",
        location="eastus",
        kind="OpenAI",
        public_network_access=False,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
        private_endpoint_connection_statuses=statuses,
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
        from prowler.providers.azure.services.aiservices.aiservices_account_uses_private_endpoint.aiservices_account_uses_private_endpoint import (
            aiservices_account_uses_private_endpoint,
        )

        return aiservices_account_uses_private_endpoint().execute()


class Test_aiservices_account_uses_private_endpoint:
    def test_no_resources(self):
        result = run_check({})
        assert len(result) == 0

    def test_no_private_endpoints(self):
        result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account([])}})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{PREFIX} has no approved private endpoint connection."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_only_pending_and_rejected_private_endpoints(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    ACCOUNT_ID: build_account(["Pending", "Rejected"])
                }
            }
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{PREFIX} has no approved private endpoint connection."
        )

    def test_approved_private_endpoint(self):
        result = run_check(
            {
                AZURE_SUBSCRIPTION_ID: {
                    ACCOUNT_ID: build_account(["Pending", "Approved"])
                }
            }
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{PREFIX} has an approved private endpoint connection."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_approved_status_is_case_insensitive(self):
        result = run_check(
            {AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(["approved"])}}
        )
        assert result[0].status == "PASS"
