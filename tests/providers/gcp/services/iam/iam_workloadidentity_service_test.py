from unittest.mock import MagicMock, patch

from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    mock_is_api_active,
    set_mocked_gcp_provider,
)

PROJECT_A = GCP_PROJECT_ID
PROJECT_B = "test-project-b"


def _pool_name(project_id, pool_id="my-pool"):
    return f"projects/{project_id}/locations/global/workloadIdentityPools/{pool_id}"


def _provider_payload(pool_name, provider_id="my-provider"):
    return {
        "name": f"{pool_name}/providers/{provider_id}",
        "state": "ACTIVE",
        "disabled": False,
        "attributeMapping": {"google.subject": "assertion.sub"},
        "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
        "displayName": "gh",
    }


def _empty_service_accounts(client):
    """Stub the service-account calls used by the rest of the IAM __init__."""
    sa = client.projects.return_value.serviceAccounts.return_value
    sa.list.return_value.execute.return_value = {"accounts": []}
    sa.list_next.return_value = None


def _wif_client(_GCPService, _service, _api_version, _credentials):
    """Discovery client stub returning one pool with one provider."""
    client = MagicMock()

    pool_name = _pool_name(GCP_PROJECT_ID)
    pools = (
        client.projects.return_value.locations.return_value.workloadIdentityPools.return_value
    )
    pools.list.return_value.execute.return_value = {
        "workloadIdentityPools": [{"name": pool_name, "state": "ACTIVE"}]
    }
    pools.list_next.return_value = None

    providers = pools.providers.return_value
    providers.list.return_value.execute.return_value = {
        "workloadIdentityPoolProviders": [_provider_payload(pool_name)]
    }
    providers.list_next.return_value = None

    _empty_service_accounts(client)
    return client


def _disabled_pool_client(_GCPService, _service, _api_version, _credentials):
    """Discovery client stub: a disabled pool containing an ACTIVE provider."""
    client = MagicMock()

    pool_name = _pool_name(GCP_PROJECT_ID)
    pools = (
        client.projects.return_value.locations.return_value.workloadIdentityPools.return_value
    )
    pools.list.return_value.execute.return_value = {
        "workloadIdentityPools": [
            {"name": pool_name, "state": "ACTIVE", "disabled": True}
        ]
    }
    pools.list_next.return_value = None

    providers = pools.providers.return_value
    providers.list.return_value.execute.return_value = {
        "workloadIdentityPoolProviders": [_provider_payload(pool_name)]
    }
    providers.list_next.return_value = None

    _empty_service_accounts(client)
    return client


def _pool_list_failure_client(_GCPService, _service, _api_version, _credentials):
    """Pool listing fails for PROJECT_A but succeeds for PROJECT_B."""
    client = MagicMock()
    pool_name_b = _pool_name(PROJECT_B)

    pools = (
        client.projects.return_value.locations.return_value.workloadIdentityPools.return_value
    )

    def pools_list(parent):
        request = MagicMock()
        if f"projects/{PROJECT_A}/" in parent:
            request.execute.side_effect = Exception("permission denied listing pools")
        else:
            request.execute.return_value = {
                "workloadIdentityPools": [{"name": pool_name_b, "state": "ACTIVE"}]
            }
        return request

    pools.list.side_effect = pools_list
    pools.list_next.return_value = None

    providers = pools.providers.return_value
    providers.list.return_value.execute.return_value = {
        "workloadIdentityPoolProviders": [_provider_payload(pool_name_b)]
    }
    providers.list_next.return_value = None

    _empty_service_accounts(client)
    return client


def _provider_list_failure_client(_GCPService, _service, _api_version, _credentials):
    """Provider listing fails for pool-1 but succeeds for pool-2 in one project."""
    client = MagicMock()
    pool_1 = _pool_name(GCP_PROJECT_ID, "pool-1")
    pool_2 = _pool_name(GCP_PROJECT_ID, "pool-2")

    pools = (
        client.projects.return_value.locations.return_value.workloadIdentityPools.return_value
    )
    pools.list.return_value.execute.return_value = {
        "workloadIdentityPools": [
            {"name": pool_1, "state": "ACTIVE"},
            {"name": pool_2, "state": "ACTIVE"},
        ]
    }
    pools.list_next.return_value = None

    providers = pools.providers.return_value

    def providers_list(parent):
        request = MagicMock()
        if parent == pool_1:
            request.execute.side_effect = Exception(
                "permission denied listing providers"
            )
        else:
            request.execute.return_value = {
                "workloadIdentityPoolProviders": [
                    _provider_payload(pool_2, provider_id="provider-2")
                ]
            }
        return request

    providers.list.side_effect = providers_list
    providers.list_next.return_value = None

    _empty_service_accounts(client)
    return client


def _run_service(client_factory, project_ids):
    with (
        patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(project_ids=project_ids),
        ),
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ),
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=client_factory,
        ),
    ):
        from prowler.providers.gcp.services.iam.iam_service import IAM

        return IAM(set_mocked_gcp_provider(project_ids=project_ids))


class TestIAMWorkloadIdentityService:
    def test_get_workload_identity_pool_providers(self):
        iam = _run_service(_wif_client, [GCP_PROJECT_ID])

        assert len(iam.workload_identity_pool_providers) == 1
        provider = iam.workload_identity_pool_providers[0]
        assert provider.id == "my-provider"
        assert provider.pool_id == "my-pool"
        assert provider.project_id == GCP_PROJECT_ID
        assert provider.state == "ACTIVE"
        assert provider.disabled is False
        assert provider.pool_disabled is False
        assert provider.attribute_condition == ""
        assert provider.provider_type == "oidc"
        assert provider.issuer_uri == "https://token.actions.githubusercontent.com"

    def test_disabled_pool_state_propagates_to_provider(self):
        iam = _run_service(_disabled_pool_client, [GCP_PROJECT_ID])

        # The provider is ACTIVE, but its parent pool is disabled: the pool's
        # effective state must travel with the provider record.
        assert len(iam.workload_identity_pool_providers) == 1
        provider = iam.workload_identity_pool_providers[0]
        assert provider.state == "ACTIVE"
        assert provider.disabled is False
        assert provider.pool_disabled is True

    def test_pool_list_failure_does_not_block_other_projects(self):
        iam = _run_service(_pool_list_failure_client, [PROJECT_A, PROJECT_B])

        # PROJECT_A's pool listing failed, but PROJECT_B is still processed.
        assert len(iam.workload_identity_pool_providers) == 1
        assert iam.workload_identity_pool_providers[0].project_id == PROJECT_B

    def test_provider_list_failure_only_skips_that_pool(self):
        iam = _run_service(_provider_list_failure_client, [GCP_PROJECT_ID])

        # pool-1's provider listing failed, but pool-2's provider is still found.
        assert len(iam.workload_identity_pool_providers) == 1
        assert iam.workload_identity_pool_providers[0].pool_id == "pool-2"
        assert iam.workload_identity_pool_providers[0].id == "provider-2"
