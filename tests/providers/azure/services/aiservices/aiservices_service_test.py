from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.aiservices.aiservices_service import (
    Account,
    AIServices,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)

ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"
SERVICE_PATH = "prowler.providers.azure.services.aiservices.aiservices_service"


def mock_get_accounts(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            ACCOUNT_ID: Account(
                id=ACCOUNT_ID,
                name="openai1",
                location="eastus",
                kind="OpenAI",
                public_network_access=True,
                disable_local_auth=False,
                encryption_key_source="Microsoft.CognitiveServices",
                encryption_key_name=None,
            )
        }
    }


def build_sdk_account(
    public_network_access="Disabled",
    disable_local_auth=True,
    encryption=None,
    properties_none=False,
):
    account = MagicMock()
    account.id = ACCOUNT_ID
    account.name = "openai1"
    account.location = "eastus"
    account.kind = "OpenAI"
    if properties_none:
        account.properties = None
        return account
    account.properties.public_network_access = public_network_access
    account.properties.disable_local_auth = disable_local_auth
    account.properties.encryption = encryption
    return account


def build_service(mock_client, resource_groups=None):
    with patch(f"{SERVICE_PATH}.AIServices._get_accounts", return_value={}):
        aiservices = AIServices(set_mocked_azure_provider())
    aiservices.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
    aiservices.resource_groups = resource_groups
    return aiservices


@patch(f"{SERVICE_PATH}.AIServices._get_accounts", new=mock_get_accounts)
class Test_AIServices_Service:
    def test_get_client(self):
        aiservices = AIServices(set_mocked_azure_provider())
        assert (
            aiservices.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "CognitiveServicesManagementClient"
        )

    def test_accounts_populated(self):
        aiservices = AIServices(set_mocked_azure_provider())
        account = aiservices.accounts[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]
        assert account.name == "openai1"
        assert account.kind == "OpenAI"


class Test_AIServices_get_accounts:
    def test_no_resource_groups_lists_subscription(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        aiservices = build_service(mock_client)

        result = aiservices._get_accounts()

        mock_client.accounts.list.assert_called_once()
        mock_client.accounts.list_by_resource_group.assert_not_called()
        account = result[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]
        assert account.public_network_access is False
        assert account.disable_local_auth is True
        assert account.encryption_key_source == "Microsoft.CognitiveServices"
        assert account.encryption_key_name is None

    def test_single_resource_group(self):
        mock_client = MagicMock()
        mock_client.accounts.list_by_resource_group.return_value = [build_sdk_account()]
        aiservices = build_service(
            mock_client, {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}
        )

        result = aiservices._get_accounts()

        mock_client.accounts.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.accounts.list.assert_not_called()
        assert ACCOUNT_ID in result[AZURE_SUBSCRIPTION_ID]

    def test_empty_resource_group_list_skips(self):
        mock_client = MagicMock()
        aiservices = build_service(mock_client, {AZURE_SUBSCRIPTION_ID: []})

        result = aiservices._get_accounts()

        mock_client.accounts.list.assert_not_called()
        mock_client.accounts.list_by_resource_group.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.accounts.list_by_resource_group.return_value = []
        aiservices = build_service(
            mock_client, {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}
        )

        aiservices._get_accounts()

        assert mock_client.accounts.list_by_resource_group.call_count == 2

    def test_public_network_access_none_treated_as_enabled(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(public_network_access=None)
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.public_network_access is True

    def test_disable_local_auth_none_treated_as_enabled_local_auth(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(disable_local_auth=None)
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.disable_local_auth is False

    def test_customer_managed_key_mapped(self):
        encryption = MagicMock()
        encryption.key_source = "Microsoft.KeyVault"
        encryption.key_vault_properties.key_name = "cmk1"
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(encryption=encryption)
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.encryption_key_source == "Microsoft.KeyVault"
        assert account.encryption_key_name == "cmk1"

    def test_properties_none_uses_safe_defaults(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(properties_none=True)
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.public_network_access is True
        assert account.disable_local_auth is False
        assert account.encryption_key_source == "Microsoft.CognitiveServices"

    def test_list_failure_leaves_subscription_empty(self):
        mock_client = MagicMock()
        mock_client.accounts.list.side_effect = Exception("boom")
        aiservices = build_service(mock_client)

        result = aiservices._get_accounts()

        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_one_bad_account_does_not_drop_others(self):
        bad = build_sdk_account()
        bad.id = None  # fails Pydantic validation: id must be str
        good = build_sdk_account()
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [bad, good]
        aiservices = build_service(mock_client)

        result = aiservices._get_accounts()

        assert list(result[AZURE_SUBSCRIPTION_ID]) == [ACCOUNT_ID]
