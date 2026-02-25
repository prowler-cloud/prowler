from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    DOMAIN,
    TENANT_IDS,
    set_mocked_azure_provider,
)


class Test_entra_require_mfa_for_management_api:
    def test_entra_no_subscriptions(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api import (
                entra_require_mfa_for_management_api,
            )

            entra_client.conditional_access_policy = {}
            entra_client.tenant_ids = TENANT_IDS

            check = entra_require_mfa_for_management_api()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_no_policies(self):
        entra_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api import (
                entra_require_mfa_for_management_api,
            )

            # No policies configured
            entra_client.conditional_access_policy = {DOMAIN: {}}
            entra_client.tenant_ids = TENANT_IDS

            check = entra_require_mfa_for_management_api()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == DOMAIN
            assert result[0].resource_id == TENANT_IDS[0]
            assert (
                result[0].status_extended
                == "Conditional Access Policy does not require MFA for management API."
            )

    def test_entra_tenant_policy_no_mfa(self):
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api import (
                entra_require_mfa_for_management_api,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]},
                access_controls={"grant": ["grant"]},
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}
            entra_client.tenant_ids = TENANT_IDS

            check = entra_require_mfa_for_management_api()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            # When policy exists but doesn't meet requirements, resource defaults to tenant
            assert result[0].resource_name == DOMAIN
            assert result[0].resource_id == TENANT_IDS[0]
            assert (
                result[0].status_extended
                == "Conditional Access Policy does not require MFA for management API."
            )

    def test_entra_tenant_policy_mfa(self):
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api import (
                entra_require_mfa_for_management_api,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]},
                access_controls={"grant": ["grant", "MFA"]},
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}
            entra_client.tenant_ids = TENANT_IDS

            check = entra_require_mfa_for_management_api()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Test Policy"
            assert result[0].resource_id == policy_id
            assert (
                result[0].status_extended
                == "Conditional Access Policy requires MFA for management API."
            )

    def test_entra_tenant_policy_mfa_disabled(self):
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api import (
                entra_require_mfa_for_management_api,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="disabled",
                users={"include": ["All"]},
                target_resources={"include": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]},
                access_controls={"grant": ["grant", "MFA"]},
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}
            entra_client.tenant_ids = TENANT_IDS

            check = entra_require_mfa_for_management_api()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            # When policy is disabled, resource defaults to tenant
            assert result[0].resource_name == DOMAIN
            assert result[0].resource_id == TENANT_IDS[0]
            assert (
                result[0].status_extended
                == "Conditional Access Policy does not require MFA for management API."
            )

    def test_entra_tenant_policy_mfa_no_target(self):
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api import (
                entra_require_mfa_for_management_api,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": ["All"]},
                target_resources={"include": []},
                access_controls={"grant": ["grant", "MFA"]},
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}
            entra_client.tenant_ids = TENANT_IDS

            check = entra_require_mfa_for_management_api()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            # When policy doesn't target management API, resource defaults to tenant
            assert result[0].resource_name == DOMAIN
            assert result[0].resource_id == TENANT_IDS[0]
            assert (
                result[0].status_extended
                == "Conditional Access Policy does not require MFA for management API."
            )

    def test_entra_tenant_policy_mfa_no_users(self):
        entra_client = mock.MagicMock
        policy_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_require_mfa_for_management_api.entra_require_mfa_for_management_api import (
                entra_require_mfa_for_management_api,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                ConditionalAccessPolicy,
            )

            policy = ConditionalAccessPolicy(
                id=policy_id,
                name="Test Policy",
                state="enabled",
                users={"include": []},
                target_resources={"include": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]},
                access_controls={"grant": ["grant", "MFA"]},
            )

            entra_client.conditional_access_policy = {DOMAIN: {policy_id: policy}}
            entra_client.tenant_ids = TENANT_IDS

            check = entra_require_mfa_for_management_api()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            # When policy doesn't include all users, resource defaults to tenant
            assert result[0].resource_name == DOMAIN
            assert result[0].resource_id == TENANT_IDS[0]
            assert (
                result[0].status_extended
                == "Conditional Access Policy does not require MFA for management API."
            )
