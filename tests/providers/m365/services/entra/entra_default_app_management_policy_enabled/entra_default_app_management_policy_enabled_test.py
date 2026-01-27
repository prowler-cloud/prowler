from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    DefaultAppManagementPolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_default_app_management_policy_enabled:
    def test_policy_enabled(self):
        """
        Test when is_enabled is True:
        The check should PASS because the default app management policy is enabled.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled import (
                entra_default_app_management_policy_enabled,
            )

            entra_client.default_app_management_policy = DefaultAppManagementPolicy(
                id="00000000-0000-0000-0000-000000000000",
                name="Default app management tenant policy",
                description="Default tenant policy that enforces app management restrictions.",
                is_enabled=True,
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Default app management policy is enabled, enforcing credential restrictions on applications and service principals."
            )
            assert result[0].resource_id == "00000000-0000-0000-0000-000000000000"
            assert result[0].location == "global"
            assert result[0].resource_name == "Default App Management Policy"
            assert (
                result[0].resource
                == entra_client.default_app_management_policy.dict()
            )

    def test_policy_disabled(self):
        """
        Test when is_enabled is False:
        The check should FAIL because the default app management policy is not enabled.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled import (
                entra_default_app_management_policy_enabled,
            )

            entra_client.default_app_management_policy = DefaultAppManagementPolicy(
                id="00000000-0000-0000-0000-000000000000",
                name="Default app management tenant policy",
                description="Default tenant policy that enforces app management restrictions.",
                is_enabled=False,
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Default app management policy is not enabled, allowing applications and service principals to be created without credential restrictions."
            )
            assert result[0].resource_id == "00000000-0000-0000-0000-000000000000"
            assert result[0].location == "global"
            assert result[0].resource_name == "Default App Management Policy"
            assert (
                result[0].resource
                == entra_client.default_app_management_policy.dict()
            )

    def test_policy_disabled_uses_tenant_domain_when_no_id(self):
        """
        Test when is_enabled is False and id is empty:
        The check should use tenant_domain as resource_id.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled import (
                entra_default_app_management_policy_enabled,
            )

            entra_client.default_app_management_policy = DefaultAppManagementPolicy(
                id="",
                name="Default app management tenant policy",
                description=None,
                is_enabled=False,
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == DOMAIN
            assert result[0].location == "global"
            assert result[0].resource_name == "Default App Management Policy"

    def test_no_policy(self):
        """
        Test when entra_client.default_app_management_policy is None:
        The check should return an empty list of findings.
        """
        entra_client = mock.MagicMock()
        entra_client.default_app_management_policy = None
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_default_app_management_policy_enabled.entra_default_app_management_policy_enabled import (
                entra_default_app_management_policy_enabled,
            )

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 0
            assert result == []
