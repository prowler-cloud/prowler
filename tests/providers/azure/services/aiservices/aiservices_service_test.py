import sys
from unittest.mock import MagicMock, patch

import pytest

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
MONITOR_CLIENT_MODULE = "prowler.providers.azure.services.monitor.monitor_client"


@pytest.fixture(autouse=True)
def monitor_client():
    """Replace the Monitor client module so no real client is built."""
    client = MagicMock()
    client.clients = {AZURE_SUBSCRIPTION_ID: MagicMock()}
    client.diagnostic_settings_with_uri.return_value = []
    with patch.dict(
        sys.modules, {MONITOR_CLIENT_MODULE: MagicMock(monitor_client=client)}
    ):
        yield client


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
    identity=None,
    private_endpoint_connections=None,
    restrict_outbound_network_access=None,
    network_acls=None,
):
    account = MagicMock()
    account.id = ACCOUNT_ID
    account.name = "openai1"
    account.location = "eastus"
    account.kind = "OpenAI"
    account.identity = identity
    if properties_none:
        account.properties = None
        return account
    account.properties.public_network_access = public_network_access
    account.properties.disable_local_auth = disable_local_auth
    account.properties.encryption = encryption
    account.properties.private_endpoint_connections = private_endpoint_connections
    account.properties.restrict_outbound_network_access = (
        restrict_outbound_network_access
    )
    account.properties.network_acls = network_acls
    return account


def build_sdk_private_endpoint_connection(status):
    connection = MagicMock()
    connection.properties.private_link_service_connection_state.status = status
    return connection


def build_sdk_deployment(
    name="gpt-4o", rai_policy_name=None, model_name="gpt-4o", capabilities=None
):
    deployment = MagicMock()
    deployment.id = f"{ACCOUNT_ID}/deployments/{name}"
    deployment.name = name
    deployment.properties.rai_policy_name = rai_policy_name
    deployment.properties.model.name = model_name
    deployment.properties.capabilities = capabilities
    return deployment


def build_sdk_rai_policy(name, content_filters):
    policy = MagicMock()
    policy.name = name
    policy.properties.content_filters = content_filters
    return policy


def build_sdk_content_filter(name, source, enabled=True, blocking=True):
    content_filter = MagicMock()
    content_filter.name = name
    content_filter.source = source
    content_filter.enabled = enabled
    content_filter.blocking = blocking
    return content_filter


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
        assert account.private_endpoint_connection_statuses == []
        assert account.restrict_outbound_network_access is False
        assert account.network_acls_default_action == "Allow"

    def test_new_fields_default_when_unset(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.private_endpoint_connection_statuses == []
        assert account.identity_type is None
        assert account.restrict_outbound_network_access is False
        assert account.network_acls_default_action == "Allow"

    def test_private_endpoint_statuses_mapped(self):
        broken = MagicMock()
        broken.properties = None
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(
                private_endpoint_connections=[
                    build_sdk_private_endpoint_connection("Approved"),
                    build_sdk_private_endpoint_connection("Pending"),
                    broken,
                ]
            )
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.private_endpoint_connection_statuses == ["Approved", "Pending"]

    def test_private_endpoint_status_enum_mapped_to_value(self):
        from azure.mgmt.cognitiveservices.models import (
            PrivateEndpointServiceConnectionStatus,
        )

        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(
                private_endpoint_connections=[
                    build_sdk_private_endpoint_connection(
                        PrivateEndpointServiceConnectionStatus.APPROVED
                    )
                ]
            )
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.private_endpoint_connection_statuses == ["Approved"]

    def test_identity_type_mapped(self):
        identity = MagicMock()
        identity.type = "SystemAssigned"
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account(identity=identity)]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.identity_type == "SystemAssigned"

    def test_restrict_outbound_network_access_mapped(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(restrict_outbound_network_access=True)
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.restrict_outbound_network_access is True

    def test_network_acls_default_action_enum_mapped_to_value(self):
        from azure.mgmt.cognitiveservices.models import NetworkRuleAction

        network_acls = MagicMock()
        network_acls.default_action = NetworkRuleAction.DENY
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(network_acls=network_acls)
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.network_acls_default_action == "Deny"

    def test_network_acls_default_action_none_treated_as_allow(self):
        network_acls = MagicMock()
        network_acls.default_action = None
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [
            build_sdk_account(network_acls=network_acls)
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.network_acls_default_action == "Allow"

    def test_deployments_and_rai_policies_mapped(self):
        from azure.mgmt.cognitiveservices.models import RaiPolicyContentSource

        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        mock_client.deployments.list.return_value = [
            build_sdk_deployment(
                rai_policy_name="Microsoft.DefaultV2",
                capabilities={"chatCompletion": "true", "area": "EUR"},
            ),
            build_sdk_deployment(name="gpt-4o-mini", rai_policy_name=""),
        ]
        mock_client.rai_policies.list.return_value = [
            build_sdk_rai_policy(
                "Microsoft.DefaultV2",
                [
                    build_sdk_content_filter(
                        "Jailbreak", RaiPolicyContentSource.PROMPT
                    ),
                    build_sdk_content_filter("Hate", "Completion", blocking=False),
                ],
            )
        ]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        mock_client.deployments.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP, account_name="openai1"
        )
        mock_client.rai_policies.list.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP, account_name="openai1"
        )
        assert [d.name for d in account.deployments] == ["gpt-4o", "gpt-4o-mini"]
        assert account.deployments[0].id == f"{ACCOUNT_ID}/deployments/gpt-4o"
        assert account.deployments[0].location == "eastus"
        assert account.deployments[0].model_name == "gpt-4o"
        assert account.deployments[0].rai_policy_name == "Microsoft.DefaultV2"
        assert account.deployments[1].rai_policy_name == ""
        assert account.deployments[0].capabilities == {
            "chatCompletion": "true",
            "area": "EUR",
        }
        assert account.deployments[1].capabilities == {}
        policy = account.rai_policies["Microsoft.DefaultV2"]
        assert policy.content_filters[0].name == "Jailbreak"
        assert policy.content_filters[0].source == "Prompt"
        assert policy.content_filters[0].enabled is True
        assert policy.content_filters[0].blocking is True
        assert policy.content_filters[1].blocking is False

    def test_deployment_without_properties_uses_empty_policy_name(self):
        deployment = build_sdk_deployment()
        deployment.properties = None
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        mock_client.deployments.list.return_value = [deployment]
        mock_client.rai_policies.list.return_value = []
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.deployments[0].rai_policy_name == ""
        assert account.deployments[0].model_name == ""
        assert account.deployments[0].capabilities == {}
        assert account.rai_policies == {}

    def test_deployments_failure_is_none(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        mock_client.deployments.list.side_effect = Exception("boom")
        mock_client.rai_policies.list.return_value = []
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.deployments is None
        assert account.rai_policies == {}

    def test_rai_policies_failure_is_none(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        mock_client.deployments.list.return_value = [build_sdk_deployment()]
        mock_client.rai_policies.list.side_effect = Exception("boom")
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert len(account.deployments) == 1
        assert account.rai_policies is None

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

    def test_diagnostic_settings_fetched_per_account(self, monitor_client):
        setting = MagicMock()
        monitor_client.diagnostic_settings_with_uri.return_value = [setting]
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        monitor_client.diagnostic_settings_with_uri.assert_called_once_with(
            AZURE_SUBSCRIPTION_ID,
            ACCOUNT_ID,
            monitor_client.clients[AZURE_SUBSCRIPTION_ID],
            raise_errors=True,
        )
        assert account.monitor_diagnostic_settings == [setting]

    def test_diagnostic_settings_none_configured_is_empty_list(self):
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.monitor_diagnostic_settings == []

    def test_diagnostic_settings_failure_is_none(self, monitor_client):
        monitor_client.diagnostic_settings_with_uri.side_effect = Exception("boom")
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        aiservices = build_service(mock_client)

        result = aiservices._get_accounts()

        assert (
            result[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID].monitor_diagnostic_settings
            is None
        )

    def test_diagnostic_settings_no_monitor_client_for_subscription_is_none(
        self, monitor_client
    ):
        monitor_client.clients = {}
        mock_client = MagicMock()
        mock_client.accounts.list.return_value = [build_sdk_account()]
        aiservices = build_service(mock_client)

        account = aiservices._get_accounts()[AZURE_SUBSCRIPTION_ID][ACCOUNT_ID]

        assert account.monitor_diagnostic_settings is None
