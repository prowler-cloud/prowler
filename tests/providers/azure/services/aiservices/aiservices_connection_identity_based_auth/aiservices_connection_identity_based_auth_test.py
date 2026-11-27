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
ACCOUNT_LOCATION = "swedencentral"


def build_connection(auth_type: str, project_name=None, name="conn1") -> Connection:
    """Build one connection, on the account or on one of its projects.

    Args:
        auth_type: The value the service returned for `authType`.
        project_name: The project holding it, or `None` for the account.
        name: The connection's name.

    Returns:
        The connection.
    """
    suffix = f"/projects/{project_name}" if project_name else ""
    return Connection(
        id=f"{ACCOUNT_ID}{suffix}/connections/{name}",
        name=name,
        auth_type=auth_type,
        category="AzureOpenAI",
        target="https://example.openai.azure.com/",
        project_name=project_name,
    )


def build_account(connections, unlisted=None) -> Account:
    """Build one AI services account holding the given connections.

    Args:
        connections: Its connections, or `None` when none could be listed.
        unlisted: Scopes whose connections could not be listed: `""` for the
            account's own, a project name for a project.

    Returns:
        The account.
    """
    return Account(
        id=ACCOUNT_ID,
        name="foundry1",
        location=ACCOUNT_LOCATION,
        kind="AIServices",
        public_network_access=False,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
        connections=connections,
        unlisted_connection_scopes=unlisted or [],
    )


def run_check(accounts):
    """Run the check against the given accounts.

    Args:
        accounts: The client's accounts, keyed by subscription then by id.

    Returns:
        The findings.
    """
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


def one(connections, unlisted=None):
    """Run the check against a single account.

    Args:
        connections: Its connections, or `None` when none could be listed.
        unlisted: Scopes whose connections could not be listed.

    Returns:
        The findings.
    """
    return run_check(
        {AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(connections, unlisted)}}
    )


class Test_aiservices_connection_identity_based_auth:
    """The check reports how each AI services connection authenticates."""

    def test_no_resources(self):
        """No accounts means no findings."""
        assert len(run_check({})) == 0

    def test_account_with_no_connections(self):
        """An account that holds no connection produces no finding."""
        assert len(one([])) == 0

    def test_connections_could_not_be_listed(self):
        """An account whose connections could not be read is MANUAL."""
        result = one(None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Connections of AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} could not be listed, so their authentication type is unknown."
        )
        assert result[0].resource_id == ACCOUNT_ID

    def test_project_connections_could_not_be_listed(self):
        """A project whose connections could not be read is MANUAL.

        The project is reported rather than left out, so connections that
        could not be read are not mistaken for connections that are absent.
        """
        result = one([], unlisted=["proj1"])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Connections of project proj1 of AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} could not be listed, so their authentication type is unknown."
        )
        assert result[0].resource_id == ACCOUNT_ID

    def test_account_scope_unlisted_alongside_project_connections(self):
        """The account's own scope is reported while its projects are read."""
        result = one([build_connection("AAD", project_name="proj1")], unlisted=[""])
        assert len(result) == 2
        manual = [r for r in result if r.status == "MANUAL"]
        assert len(manual) == 1
        assert (
            manual[0].status_extended
            == f"Connections of AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} could not be listed, so their authentication type is unknown."
        )
        assert [r.status for r in result if r.status != "MANUAL"] == ["PASS"]

    def test_api_key_fails(self):
        """A connection holding an API key fails."""
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
        """A connection authenticating as a directory identity passes."""
        result = one([build_connection("AAD")])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Connection conn1 in AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} authenticates with the identity type AAD."
        )

    def test_agent_identity_passes(self):
        """An agent identity type passes, though the SDK enum omits it."""
        result = one([build_connection("AgenticIdentityToken")])
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_project_connection_names_its_project(self):
        """A project level connection names its project in the finding."""
        result = one([build_connection("ApiKey", project_name="proj1")])
        assert len(result) == 1
        assert (
            result[0].status_extended
            == f"Connection conn1 in project proj1 of AI services account foundry1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} authenticates with the stored credential type ApiKey, which carries no caller identity."
        )

    def test_no_auth_fails(self):
        """A connection with no authentication configured fails."""
        result = one([build_connection("None")])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "has no authentication configured" in result[0].status_extended

    def test_empty_auth_type_fails(self):
        """An empty authentication type fails."""
        result = one([build_connection("")])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_unknown_auth_type_is_manual(self):
        """An authentication type the check does not know is MANUAL."""
        result = one([build_connection("SomethingNew")])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "does not recognise" in result[0].status_extended

    def test_one_finding_per_connection(self):
        """Each connection on an account gets its own finding."""
        result = one(
            [
                build_connection("ApiKey", name="a"),
                build_connection("AAD", name="b", project_name="proj1"),
            ]
        )
        assert len(result) == 2
        assert sorted(r.status for r in result) == ["FAIL", "PASS"]

    def test_findings_carry_the_account_location(self):
        """A connection has no location of its own, so the account's is used.

        Without this the finding falls back to the global default and the
        output cannot be grouped or filtered by region.
        """
        result = one([build_connection("ApiKey")], unlisted=["proj1"])
        assert len(result) == 2
        assert {r.location for r in result} == {ACCOUNT_LOCATION}
        assert all(r.location != "global" for r in result)

    def test_unreadable_account_finding_carries_the_account_location(self):
        """The account level MANUAL finding carries the account's location."""
        result = one(None)
        assert result[0].location == ACCOUNT_LOCATION
