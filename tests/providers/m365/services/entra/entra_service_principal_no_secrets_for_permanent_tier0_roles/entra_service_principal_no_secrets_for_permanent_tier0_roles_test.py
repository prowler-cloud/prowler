from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    KeyCredential,
    PasswordCredential,
    ServicePrincipal,
    TIER_0_ROLE_TEMPLATE_IDS,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_service_principal_no_secrets_for_permanent_tier0_roles:
    """Tests for the entra_service_principal_no_secrets_for_permanent_tier0_roles check."""

    def test_no_service_principals(self):
        """No service principals configured: expected no findings."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles import (
                entra_service_principal_no_secrets_for_permanent_tier0_roles,
            )

            entra_client.service_principals = {}

            check = entra_service_principal_no_secrets_for_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 0

    def test_service_principal_no_secrets_no_roles(self):
        """Service principal without secrets and no Tier 0 roles: expected PASS."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles import (
                entra_service_principal_no_secrets_for_permanent_tier0_roles,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="TestApp",
                    app_id=str(uuid4()),
                    password_credentials=[],
                    key_credentials=[
                        KeyCredential(key_id=str(uuid4()), display_name="cert1")
                    ],
                    directory_role_template_ids=[],
                )
            }

            check = entra_service_principal_no_secrets_for_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not use client secrets" in result[0].status_extended
            assert result[0].resource_id == sp_id
            assert result[0].resource_name == "TestApp"

    def test_service_principal_with_secrets_no_tier0_roles(self):
        """Service principal with secrets but no Tier 0 roles: expected PASS."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        non_tier0_role = "fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Administrator

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles import (
                entra_service_principal_no_secrets_for_permanent_tier0_roles,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="AppWithSecrets",
                    app_id=str(uuid4()),
                    password_credentials=[
                        PasswordCredential(key_id=str(uuid4()), display_name="secret1")
                    ],
                    key_credentials=[],
                    directory_role_template_ids=[non_tier0_role],
                )
            }

            check = entra_service_principal_no_secrets_for_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no permanent Tier 0" in result[0].status_extended
            assert result[0].resource_id == sp_id

    def test_service_principal_no_secrets_with_tier0_roles(self):
        """Service principal without secrets but with Tier 0 roles: expected PASS."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        global_admin_role = "62e90394-69f5-4237-9190-012177145e10"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles import (
                entra_service_principal_no_secrets_for_permanent_tier0_roles,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="CertBasedApp",
                    app_id=str(uuid4()),
                    password_credentials=[],
                    key_credentials=[
                        KeyCredential(key_id=str(uuid4()), display_name="cert1")
                    ],
                    directory_role_template_ids=[global_admin_role],
                )
            }

            check = entra_service_principal_no_secrets_for_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not use client secrets" in result[0].status_extended
            assert result[0].resource_id == sp_id

    def test_service_principal_with_secrets_and_tier0_role(self):
        """Service principal with secrets and Tier 0 role: expected FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        global_admin_role = "62e90394-69f5-4237-9190-012177145e10"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles import (
                entra_service_principal_no_secrets_for_permanent_tier0_roles,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="VulnerableApp",
                    app_id=str(uuid4()),
                    password_credentials=[
                        PasswordCredential(key_id=str(uuid4()), display_name="secret1")
                    ],
                    key_credentials=[],
                    directory_role_template_ids=[global_admin_role],
                )
            }

            check = entra_service_principal_no_secrets_for_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "uses client secrets" in result[0].status_extended
            assert "Control Plane" in result[0].status_extended
            assert result[0].resource_id == sp_id
            assert result[0].resource_name == "VulnerableApp"

    def test_service_principal_with_secrets_and_multiple_tier0_roles(self):
        """Service principal with secrets and multiple Tier 0 roles: expected FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        global_admin_role = "62e90394-69f5-4237-9190-012177145e10"
        priv_role_admin = "e8611ab8-c189-46e8-94e1-60213ab1f814"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles import (
                entra_service_principal_no_secrets_for_permanent_tier0_roles,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="HighRiskApp",
                    app_id=str(uuid4()),
                    password_credentials=[
                        PasswordCredential(key_id=str(uuid4()), display_name="secret1"),
                        PasswordCredential(key_id=str(uuid4()), display_name="secret2"),
                    ],
                    key_credentials=[],
                    directory_role_template_ids=[
                        global_admin_role,
                        priv_role_admin,
                    ],
                )
            }

            check = entra_service_principal_no_secrets_for_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "2 Control Plane" in result[0].status_extended

    def test_multiple_service_principals_mixed(self):
        """Multiple service principals with mixed states: mixed results."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id_pass = str(uuid4())
        sp_id_fail = str(uuid4())
        global_admin_role = "62e90394-69f5-4237-9190-012177145e10"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_no_secrets_for_permanent_tier0_roles.entra_service_principal_no_secrets_for_permanent_tier0_roles import (
                entra_service_principal_no_secrets_for_permanent_tier0_roles,
            )

            entra_client.service_principals = {
                sp_id_pass: ServicePrincipal(
                    id=sp_id_pass,
                    name="SafeApp",
                    app_id=str(uuid4()),
                    password_credentials=[],
                    key_credentials=[
                        KeyCredential(key_id=str(uuid4()), display_name="cert1")
                    ],
                    directory_role_template_ids=[global_admin_role],
                ),
                sp_id_fail: ServicePrincipal(
                    id=sp_id_fail,
                    name="UnsafeApp",
                    app_id=str(uuid4()),
                    password_credentials=[
                        PasswordCredential(key_id=str(uuid4()), display_name="secret1")
                    ],
                    key_credentials=[],
                    directory_role_template_ids=[global_admin_role],
                ),
            }

            check = entra_service_principal_no_secrets_for_permanent_tier0_roles()
            result = check.execute()

            assert len(result) == 2
            statuses = {r.resource_id: r.status for r in result}
            assert statuses[sp_id_pass] == "PASS"
            assert statuses[sp_id_fail] == "FAIL"
