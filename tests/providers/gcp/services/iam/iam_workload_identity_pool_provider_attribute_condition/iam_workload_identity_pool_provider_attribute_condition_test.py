from unittest import mock

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    set_mocked_gcp_provider,
)

CHECK_MODULE = "prowler.providers.gcp.services.iam.iam_workload_identity_pool_provider_attribute_condition.iam_workload_identity_pool_provider_attribute_condition"


def _run(provider_kwargs):
    iam_client = mock.MagicMock()
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ),
        mock.patch(f"{CHECK_MODULE}.iam_client", new=iam_client),
    ):
        from prowler.providers.gcp.services.iam.iam_service import (
            WorkloadIdentityPoolProvider,
        )
        from prowler.providers.gcp.services.iam.iam_workload_identity_pool_provider_attribute_condition.iam_workload_identity_pool_provider_attribute_condition import (
            iam_workload_identity_pool_provider_attribute_condition,
        )

        providers = []
        for kwargs in provider_kwargs:
            provider_id = kwargs.get("provider_id", "my-provider")
            providers.append(
                WorkloadIdentityPoolProvider(
                    name=(
                        f"projects/{GCP_PROJECT_ID}/locations/global/"
                        f"workloadIdentityPools/my-pool/providers/{provider_id}"
                    ),
                    id=provider_id,
                    pool_id="my-pool",
                    pool_disabled=kwargs.get("pool_disabled", False),
                    project_id=GCP_PROJECT_ID,
                    state=kwargs.get("state", "ACTIVE"),
                    disabled=kwargs.get("disabled", False),
                    attribute_condition=kwargs.get("attribute_condition", ""),
                    provider_type=kwargs.get("provider_type", "oidc"),
                    issuer_uri=kwargs.get(
                        "issuer_uri",
                        "https://token.actions.githubusercontent.com",
                    ),
                    display_name="My Provider",
                )
            )

        iam_client.project_ids = [GCP_PROJECT_ID]
        iam_client.region = GCP_US_CENTER1_LOCATION
        iam_client.workload_identity_pool_providers = providers
        return iam_workload_identity_pool_provider_attribute_condition().execute()


class Test_iam_workload_identity_pool_provider_attribute_condition:
    def test_no_providers(self):
        assert len(_run([])) == 0

    def test_multi_tenant_issuer_without_attribute_condition_fails(self):
        result = _run(
            [
                {
                    "attribute_condition": "",
                    "issuer_uri": "https://token.actions.githubusercontent.com",
                }
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id.endswith("my-provider")
        assert result[0].location == "global"
        assert "multi-tenant issuer" in result[0].status_extended

    def test_dedicated_issuer_without_attribute_condition_passes(self):
        result = _run(
            [
                {
                    "attribute_condition": "",
                    "issuer_uri": "https://oidc.eks.eu-west-1.amazonaws.com/id/ABC123",
                }
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "dedicated issuer" in result[0].status_extended

    def test_non_oidc_provider_without_attribute_condition_passes(self):
        result = _run(
            [{"attribute_condition": "", "provider_type": "aws", "issuer_uri": ""}]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "not an OIDC provider" in result[0].status_extended

    def test_multi_tenant_issuer_with_port_and_uppercase_fails(self):
        result = _run(
            [{"attribute_condition": "", "issuer_uri": "https://GitLab.com:443"}]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_multi_tenant_issuer_bare_host_fails(self):
        result = _run(
            [
                {
                    "attribute_condition": "",
                    "issuer_uri": "token.actions.githubusercontent.com",
                }
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_multi_tenant_issuer_with_attribute_condition_passes(self):
        result = _run(
            [
                {
                    "attribute_condition": "assertion.repository_owner == 'acme'",
                    "issuer_uri": "https://token.actions.githubusercontent.com",
                }
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "enforces an attribute condition" in result[0].status_extended

    def test_disabled_provider_passes(self):
        result = _run([{"disabled": True}])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "not active" in result[0].status_extended

    def test_non_active_provider_passes(self):
        result = _run([{"state": "DELETED"}])
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_active_provider_in_disabled_pool_passes(self):
        # The provider itself is ACTIVE and unconditioned on a multi-tenant
        # issuer, but its parent pool is disabled and cannot vend credentials.
        result = _run([{"pool_disabled": True}])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "disabled pool" in result[0].status_extended
