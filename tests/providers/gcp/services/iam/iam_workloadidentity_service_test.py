from unittest.mock import MagicMock, patch

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def _wif_client(_GCPService, _service, _api_version, _credentials):
    """Discovery client stub returning one pool with one provider."""
    client = MagicMock()

    pool_name = (
        f"projects/{GCP_PROJECT_ID}/locations/global/workloadIdentityPools/my-pool"
    )
    pools = (
        client.projects.return_value.locations.return_value.workloadIdentityPools.return_value
    )
    pools.list.return_value.execute.return_value = {
        "workloadIdentityPools": [{"name": pool_name, "state": "ACTIVE"}]
    }
    pools.list_next.return_value = None

    providers = pools.providers.return_value
    providers.list.return_value.execute.return_value = {
        "workloadIdentityPoolProviders": [
            {
                "name": f"{pool_name}/providers/my-provider",
                "state": "ACTIVE",
                "disabled": False,
                "attributeMapping": {"google.subject": "assertion.sub"},
                "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                "displayName": "gh",
            }
        ]
    }
    providers.list_next.return_value = None

    # Service accounts calls used by the rest of the IAM service __init__.
    sa = client.projects.return_value.serviceAccounts.return_value
    sa.list.return_value.execute.return_value = {"accounts": []}
    sa.list_next.return_value = None
    return client


class TestIAMWorkloadIdentityService:
    def test_get_workload_identity_pool_providers(self):
        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]),
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
                new=mock_is_api_active,
            ),
            patch(
                "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
                new=_wif_client,
            ),
        ):
            from prowler.providers.gcp.services.iam.iam_service import IAM

            iam = IAM(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

            assert len(iam.workload_identity_pool_providers) == 1
            provider = iam.workload_identity_pool_providers[0]
            assert provider.id == "my-provider"
            assert provider.pool_id == "my-pool"
            assert provider.project_id == GCP_PROJECT_ID
            assert provider.state == "ACTIVE"
            assert provider.disabled is False
            assert provider.attribute_condition == ""
            assert provider.provider_type == "oidc"
