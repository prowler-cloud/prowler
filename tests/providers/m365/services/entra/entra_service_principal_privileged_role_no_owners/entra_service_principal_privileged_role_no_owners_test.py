from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import ServicePrincipal
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

GLOBAL_ADMIN_ROLE = "62e90394-69f5-4237-9190-012177145e10"
PRIV_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"


class Test_entra_service_principal_privileged_role_no_owners:
    """Tests for the entra_service_principal_privileged_role_no_owners check."""

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
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {}

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 0

    def test_service_principal_no_tier0_roles(self):
        """Service principal without Tier 0 roles: expected PASS."""
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
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="NonPrivilegedApp",
                    app_id=str(uuid4()),
                    directory_role_template_ids=[],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == sp_id
            assert result[0].resource_name == "NonPrivilegedApp"
            assert (
                "no permanent Tier 0 directory role assignments"
                in result[0].status_extended
            )

    def test_service_principal_tier0_no_owners(self):
        """Privileged SP with no owners on SP or app: expected PASS."""
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
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="SecureApp",
                    app_id=str(uuid4()),
                    directory_role_template_ids=[GLOBAL_ADMIN_ROLE],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == sp_id
            assert result[0].resource_name == "SecureApp"
            assert "no owners" in result[0].status_extended

    def test_service_principal_tier0_with_sp_owners(self):
        """Privileged SP with owners on SP only: expected FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        owner_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="RiskyApp",
                    app_id=str(uuid4()),
                    directory_role_template_ids=[GLOBAL_ADMIN_ROLE],
                    sp_owner_ids=[owner_id],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == sp_id
            assert "1 owner(s)" in result[0].status_extended
            assert "1 on the service principal" in result[0].status_extended
            assert "0 on the parent app registration" in result[0].status_extended

    def test_service_principal_tier0_with_app_owners(self):
        """Privileged SP with owners on parent app only: expected FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        app_owner_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="AppRegOwnerRisk",
                    app_id=str(uuid4()),
                    directory_role_template_ids=[GLOBAL_ADMIN_ROLE],
                    sp_owner_ids=[],
                    app_owner_ids=[app_owner_id],
                )
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 owner(s)" in result[0].status_extended
            assert "0 on the service principal" in result[0].status_extended
            assert "1 on the parent app registration" in result[0].status_extended

    def test_service_principal_tier0_with_both_owners(self):
        """Privileged SP with distinct owners on both SP and app: expected FAIL."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        sp_owner_id = str(uuid4())
        app_owner_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="HighRiskApp",
                    app_id=str(uuid4()),
                    directory_role_template_ids=[GLOBAL_ADMIN_ROLE, PRIV_ROLE_ADMIN],
                    sp_owner_ids=[sp_owner_id],
                    app_owner_ids=[app_owner_id],
                )
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "2 permanent Tier 0 directory role(s)" in result[0].status_extended
            assert "2 owner(s)" in result[0].status_extended

    def test_service_principal_tier0_same_owner_on_sp_and_app(self):
        """Same principal owns both SP and parent app: owner count deduplicated."""
        entra_client = mock.MagicMock
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        shared_owner_id = str(uuid4())

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_role_no_owners.entra_service_principal_privileged_role_no_owners import (
                entra_service_principal_privileged_role_no_owners,
            )

            entra_client.service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="DualOwnedApp",
                    app_id=str(uuid4()),
                    directory_role_template_ids=[GLOBAL_ADMIN_ROLE],
                    sp_owner_ids=[shared_owner_id],
                    app_owner_ids=[shared_owner_id],
                )
            }

            check = entra_service_principal_privileged_role_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1 owner(s)" in result[0].status_extended
            assert "1 on the service principal" in result[0].status_extended
            assert "1 on the parent app registration" in result[0].status_extended
