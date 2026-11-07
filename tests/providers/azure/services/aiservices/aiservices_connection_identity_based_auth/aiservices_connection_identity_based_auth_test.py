from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import (
    Account,
    Connection,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_connection_identity_based_auth"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/foundry1"


def build_connection(auth_type: str, project_name=None, name="conn1") -> Connection:
    suffix = f"/projects/{project_name}" if project_name else ""
    return Connection(
        id=f"{ACCOUNT_ID}{suffix}/connections/{name}",
        name=name,
        auth_type=auth_type,
        category="AzureOpenAI",
        target="https://example.openai.azure.com/",
        project_name=project_name,
    )


def build_account(connections) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="foundry1",
        location="swedencentral",
        kind="AIServices",
        public_network_access=False,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
        connections=connections,
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
        from prowler.providers.azure.services.aiservices.aiservices_connection_identity_based_auth.aiservices_connection_identity_based_auth import (
            aiservices_connection_identity_based_auth,
        )

        return aiservices_connection_identity_based_auth().execute()


def one(connections):
    return run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(connections)}})


class Test_aiservices_connection_identity_based_auth:
    def test_no_resources(self):
        assert len(run_check({})) == 0

    def test_account_with_no_connections(self):
        assert len(one([])) == 0

    def test_connections_could_not_be_listed(self):
        result = one(None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Connections of AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} could not be listed, so their authentication type is unknown."
        )
        assert result[0].resource_id == ACCOUNT_ID

    def test_api_key_fails(self):
        result = one([build_connection("ApiKey")])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Connection conn1 in AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} authenticates with the stored credential type ApiKey, which carries no caller identity."
        )
        assert result[0].resource_name == "conn1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_aad_passes(self):
        result = one([build_connection("AAD")])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Connection conn1 in AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} authenticates with the identity type AAD."
        )

    def test_agent_identity_passes(self):
        # Not in the SDK enum, and accepted by the service.
        result = one([build_connection("AgenticIdentityToken")])
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_project_connection_names_its_project(self):
        result = one([build_connection("ApiKey", project_name="proj1")])
        assert len(result) == 1
        assert (
            result[0].status_extended
            == f"Connection conn1 in project proj1 of AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} authenticates with the stored credential type ApiKey, which carries no caller identity."
        )

    def test_no_auth_fails(self):
        result = one([build_connection("None")])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "has no authentication configured" in result[0].status_extended

    def test_empty_auth_type_fails(self):
        result = one([build_connection("")])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_unknown_auth_type_is_manual(self):
        result = one([build_connection("SomethingNew")])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "does not recognise" in result[0].status_extended

    def test_one_finding_per_connection(self):
        result = one(
            [
                build_connection("ApiKey", name="a"),
                build_connection("AAD", name="b", project_name="proj1"),
            ]
        )
        assert len(result) == 2
        assert sorted(r.status for r in result) == ["FAIL", "PASS"]
