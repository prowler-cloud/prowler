from typing import Optional
from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import (
    Account,
    ContentFilter,
    Deployment,
    RaiPolicy,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_deployment_content_filter_prompt_shield_enabled"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"
DEPLOYMENT_ID = f"{ACCOUNT_ID}/deployments/gpt-4o"
PREFIX = f"AI services deployment gpt-4o (model gpt-4o) in account openai1 from subscription {AZURE_SUBSCRIPTION_DISPLAY}"


def jailbreak_filter(enabled=True, blocking=True, source="Prompt") -> ContentFilter:
    return ContentFilter(
        name="Jailbreak", source=source, enabled=enabled, blocking=blocking
    )


def build_account(
    rai_policy_name: str = "Microsoft.DefaultV2",
    rai_policies: Optional[dict] = None,
    deployments: Optional[list] = "default",
    capabilities: Optional[dict] = None,
) -> Account:
    if deployments == "default":
        deployments = [
            Deployment(
                id=DEPLOYMENT_ID,
                name="gpt-4o",
                location="eastus",
                model_name="gpt-4o",
                rai_policy_name=rai_policy_name,
                capabilities=(
                    {"chatCompletion": "true"} if capabilities is None else capabilities
                ),
            )
        ]
    return Account(
        id=ACCOUNT_ID,
        name="openai1",
        location="eastus",
        kind="OpenAI",
        public_network_access=False,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
        deployments=deployments,
        rai_policies=rai_policies,
    )


def policies(*content_filters, name="Microsoft.DefaultV2") -> dict:
    return {name: RaiPolicy(name=name, content_filters=list(content_filters))}


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
        from prowler.providers.azure.services.aiservices.aiservices_deployment_content_filter_prompt_shield_enabled.aiservices_deployment_content_filter_prompt_shield_enabled import (
            aiservices_deployment_content_filter_prompt_shield_enabled,
        )

        return aiservices_deployment_content_filter_prompt_shield_enabled().execute()


def single(account):
    result = run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: account}})
    assert len(result) == 1
    assert result[0].subscription == AZURE_SUBSCRIPTION_ID
    return result[0]


class Test_aiservices_deployment_content_filter_prompt_shield_enabled:
    def test_no_resources(self):
        assert run_check({}) == []

    def test_account_without_deployments(self):
        assert (
            run_check(
                {AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(deployments=[])}}
            )
            == []
        )

    def test_jailbreak_filter_blocking(self):
        finding = single(build_account(rai_policies=policies(jailbreak_filter())))
        assert finding.status == "PASS"
        assert (
            finding.status_extended
            == f"{PREFIX} uses content filter policy Microsoft.DefaultV2, which blocks jailbreak attempts with Prompt Shields."
        )
        assert finding.resource_id == DEPLOYMENT_ID
        assert finding.resource_name == "gpt-4o"
        assert finding.location == "eastus"

    def test_jailbreak_filter_match_is_case_insensitive(self):
        content_filter = ContentFilter(
            name="jailbreak", source="prompt", enabled=True, blocking=True
        )
        finding = single(build_account(rai_policies=policies(content_filter)))
        assert finding.status == "PASS"

    def test_jailbreak_filter_missing(self):
        finding = single(
            build_account(
                rai_policy_name="Microsoft.Default",
                rai_policies=policies(
                    ContentFilter(
                        name="Hate", source="Prompt", enabled=True, blocking=True
                    ),
                    name="Microsoft.Default",
                ),
            )
        )
        assert finding.status == "FAIL"
        assert (
            finding.status_extended
            == f"{PREFIX} uses content filter policy Microsoft.Default, which does not block jailbreak attempts with Prompt Shields."
        )
        assert finding.resource_id == DEPLOYMENT_ID

    def test_jailbreak_filter_disabled(self):
        finding = single(
            build_account(rai_policies=policies(jailbreak_filter(enabled=False)))
        )
        assert finding.status == "FAIL"

    def test_jailbreak_filter_annotate_only(self):
        finding = single(
            build_account(rai_policies=policies(jailbreak_filter(blocking=False)))
        )
        assert finding.status == "FAIL"

    def test_jailbreak_filter_on_completion_only(self):
        finding = single(
            build_account(rai_policies=policies(jailbreak_filter(source="Completion")))
        )
        assert finding.status == "FAIL"

    def test_policy_name_match_is_case_insensitive(self):
        finding = single(
            build_account(
                rai_policy_name="microsoft.defaultv2",
                rai_policies=policies(jailbreak_filter()),
            )
        )
        assert finding.status == "PASS"

    def test_embeddings_deployment_is_skipped(self):
        account = build_account(
            rai_policy_name="",
            rai_policies=policies(jailbreak_filter()),
            capabilities={"embeddings": "true", "area": "EUR"},
        )
        assert run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: account}}) == []

    def test_text_capability_set_to_false_is_skipped(self):
        account = build_account(
            rai_policies=policies(jailbreak_filter()),
            capabilities={"chatCompletion": "false"},
        )
        assert run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: account}}) == []

    def test_missing_capabilities_is_evaluated(self):
        finding = single(
            build_account(rai_policies=policies(jailbreak_filter()), capabilities={})
        )
        assert finding.status == "PASS"

    def test_default_policy_is_manual(self):
        finding = single(
            build_account(rai_policy_name="", rai_policies=policies(jailbreak_filter()))
        )
        assert finding.status == "MANUAL"
        assert (
            finding.status_extended
            == f"{PREFIX} uses the account default content filter policy, which Azure does not identify. Confirm that it blocks jailbreak attempts with Prompt Shields."
        )
        assert finding.resource_id == DEPLOYMENT_ID

    def test_policies_unreadable_is_manual(self):
        finding = single(build_account(rai_policies=None))
        assert finding.status == "MANUAL"
        assert (
            finding.status_extended
            == f"{PREFIX} uses content filter policy Microsoft.DefaultV2, which could not be read."
        )

    def test_policy_not_found_is_manual(self):
        finding = single(
            build_account(
                rai_policy_name="custom-policy",
                rai_policies=policies(jailbreak_filter()),
            )
        )
        assert finding.status == "MANUAL"
        assert (
            finding.status_extended
            == f"{PREFIX} uses content filter policy custom-policy, which was not found on the account."
        )

    def test_deployments_unreadable_is_manual(self):
        finding = single(build_account(deployments=None, rai_policies={}))
        assert finding.status == "MANUAL"
        assert (
            finding.status_extended
            == f"Deployments of AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY} could not be read."
        )
        assert finding.resource_id == ACCOUNT_ID
        assert finding.resource_name == "openai1"
