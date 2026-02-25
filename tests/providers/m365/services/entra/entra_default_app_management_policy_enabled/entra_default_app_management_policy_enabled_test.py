from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AppManagementRestrictions,
    CredentialRestriction,
    DefaultAppManagementPolicy,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

POLICY_ID = "00000000-0000-0000-0000-000000000000"
POLICY_NAME = "Default app management tenant policy"
POLICY_DESCRIPTION = "Default tenant policy that enforces app management restrictions."

ALL_PASSWORD_RESTRICTIONS = [
    CredentialRestriction(
        restriction_type="passwordAddition",
        state="enabled",
    ),
    CredentialRestriction(
        restriction_type="passwordLifetime",
        state="enabled",
        max_lifetime="P365D",
    ),
    CredentialRestriction(
        restriction_type="customPasswordAddition",
        state="enabled",
    ),
]

ALL_KEY_RESTRICTIONS = [
    CredentialRestriction(
        restriction_type="asymmetricKeyLifetime",
        state="enabled",
        max_lifetime="P365D",
    ),
]


class Test_entra_default_app_management_policy_enabled:
    def test_all_restrictions_configured(self):
        """All required restrictions are present and enabled -> PASS."""
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
                id=POLICY_ID,
                name=POLICY_NAME,
                description=POLICY_DESCRIPTION,
                is_enabled=True,
                application_restrictions=AppManagementRestrictions(
                    password_credentials=ALL_PASSWORD_RESTRICTIONS,
                    key_credentials=ALL_KEY_RESTRICTIONS,
                ),
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "all required credential restrictions" in result[0].status_extended
            assert result[0].resource_id == POLICY_ID
            assert result[0].resource_name == "Default App Management Policy"

    def test_missing_password_restriction(self):
        """Missing customPasswordAddition restriction -> FAIL."""
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
                id=POLICY_ID,
                name=POLICY_NAME,
                description=POLICY_DESCRIPTION,
                is_enabled=True,
                application_restrictions=AppManagementRestrictions(
                    password_credentials=[
                        CredentialRestriction(
                            restriction_type="passwordAddition",
                            state="enabled",
                        ),
                        CredentialRestriction(
                            restriction_type="passwordLifetime",
                            state="enabled",
                            max_lifetime="P365D",
                        ),
                    ],
                    key_credentials=ALL_KEY_RESTRICTIONS,
                ),
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Block custom passwords" in result[0].status_extended

    def test_missing_key_restriction(self):
        """Missing asymmetricKeyLifetime restriction -> FAIL."""
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
                id=POLICY_ID,
                name=POLICY_NAME,
                description=POLICY_DESCRIPTION,
                is_enabled=True,
                application_restrictions=AppManagementRestrictions(
                    password_credentials=ALL_PASSWORD_RESTRICTIONS,
                    key_credentials=[],
                ),
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Restrict max certificate lifetime" in result[0].status_extended

    def test_no_restrictions_configured(self):
        """Policy enabled but no restrictions at all -> FAIL listing all missing."""
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
                id=POLICY_ID,
                name=POLICY_NAME,
                description=POLICY_DESCRIPTION,
                is_enabled=True,
                application_restrictions=AppManagementRestrictions(),
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Block password addition" in result[0].status_extended
            assert "Restrict max password lifetime" in result[0].status_extended
            assert "Block custom passwords" in result[0].status_extended
            assert "Restrict max certificate lifetime" in result[0].status_extended

    def test_restriction_with_disabled_state(self):
        """Restrictions present but with state disabled -> FAIL."""
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
                id=POLICY_ID,
                name=POLICY_NAME,
                description=POLICY_DESCRIPTION,
                is_enabled=True,
                application_restrictions=AppManagementRestrictions(
                    password_credentials=[
                        CredentialRestriction(
                            restriction_type="passwordAddition",
                            state="disabled",
                        ),
                        CredentialRestriction(
                            restriction_type="passwordLifetime",
                            state="enabled",
                            max_lifetime="P365D",
                        ),
                        CredentialRestriction(
                            restriction_type="customPasswordAddition",
                            state="enabled",
                        ),
                    ],
                    key_credentials=ALL_KEY_RESTRICTIONS,
                ),
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Block password addition" in result[0].status_extended

    def test_policy_not_enabled(self):
        """Policy isEnabled is False -> FAIL."""
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
                id=POLICY_ID,
                name=POLICY_NAME,
                description=POLICY_DESCRIPTION,
                is_enabled=False,
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not enabled" in result[0].status_extended

    def test_uses_tenant_domain_when_no_id(self):
        """When policy id is empty, resource_id falls back to tenant_domain."""
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
                name=POLICY_NAME,
                description=None,
                is_enabled=True,
                application_restrictions=AppManagementRestrictions(),
            )
            entra_client.tenant_domain = DOMAIN

            check = entra_default_app_management_policy_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == DOMAIN

    def test_no_policy(self):
        """When policy is None, return empty findings."""
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
