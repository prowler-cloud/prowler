from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import ServicePrincipal
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_service_principal_non_microsoft_assignment_required."
    "entra_service_principal_non_microsoft_assignment_required"
)

MICROSOFT_TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
MICROSOFT_TENANT_ID_2 = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
THIRD_PARTY_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"


class Test_entra_service_principal_non_microsoft_assignment_required:
    """Tests for the entra_service_principal_non_microsoft_assignment_required check."""

    def _run_check(self, entra_client):
        """Helper to execute the check with the mocked client."""
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE}.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_service_principal_non_microsoft_assignment_required.entra_service_principal_non_microsoft_assignment_required import (
                entra_service_principal_non_microsoft_assignment_required,
            )

            check = entra_service_principal_non_microsoft_assignment_required()
            return check.execute()

    def _make_client(self, enterprise_apps=None, enterprise_apps_error=None):
        """Create a mock entra_client with the given enterprise apps data."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.enterprise_apps = enterprise_apps
        entra_client.enterprise_apps_error = enterprise_apps_error
        entra_client.audit_config = {}
        return entra_client

    def test_enterprise_apps_error_returns_manual(self):
        """When enterprise apps could not be retrieved, emit a single MANUAL finding."""
        client = self._make_client(
            enterprise_apps=None,
            enterprise_apps_error="ODataError: Insufficient privileges",
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "servicePrincipals"
        assert result[0].resource_name == "Enterprise applications"
        assert "Insufficient privileges" in result[0].status_extended

    def test_enterprise_apps_error_unknown(self):
        """When enterprise apps is None with no error detail, the message says 'unknown error'."""
        client = self._make_client(
            enterprise_apps=None,
            enterprise_apps_error=None,
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "servicePrincipals"
        assert "unknown error" in result[0].status_extended

    def test_no_enterprise_apps(self):
        """Empty enterprise apps dict: no findings."""
        client = self._make_client(enterprise_apps={})

        result = self._run_check(client)

        assert len(result) == 0

    def test_assignment_required_pass(self):
        """Service principal with appRoleAssignmentRequired=True: PASS."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Contoso CRM",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=True,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == sp_id
        assert result[0].resource_name == "Contoso CRM"
        assert "requires explicit user assignment" in result[0].status_extended

    def test_assignment_not_required_fail(self):
        """Enabled SP with appRoleAssignmentRequired=False: FAIL."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Contoso CRM",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == sp_id
        assert "does not require user assignment" in result[0].status_extended
        assert "any user in the tenant" in result[0].status_extended

    def test_disabled_sp_assignment_not_required_pass(self):
        """Disabled SP with appRoleAssignmentRequired=False: PASS with advisory."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Old App",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=False,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "disabled" in result[0].status_extended
        assert "re-enabled" in result[0].status_extended

    def test_disabled_sp_assignment_required_pass(self):
        """Disabled SP with appRoleAssignmentRequired=True: PASS (normal message, not disabled advisory)."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Disabled Compliant App",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=False,
                    app_role_assignment_required=True,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "requires explicit user assignment" in result[0].status_extended
        # Should NOT mention disabled/re-enabled since assignment is already required
        assert "disabled" not in result[0].status_extended

    def test_microsoft_first_party_excluded(self):
        """Microsoft first-party service principals (primary tenant ID) are excluded."""
        sp_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Microsoft Graph",
                    app_id=str(uuid4()),
                    app_owner_organization_id=MICROSOFT_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 0

    def test_microsoft_second_first_party_tenant_excluded(self):
        """Microsoft first-party service principals (second tenant ID) are also excluded."""
        sp_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Microsoft Office",
                    app_id=str(uuid4()),
                    app_owner_organization_id=MICROSOFT_TENANT_ID_2,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 0

    def test_managed_identity_excluded(self):
        """ManagedIdentity service principals are excluded."""
        sp_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="My Managed Identity",
                    app_id=str(uuid4()),
                    service_principal_type="ManagedIdentity",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 0

    def test_social_idp_excluded(self):
        """SocialIdp service principals are excluded."""
        sp_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Google",
                    app_id=str(uuid4()),
                    service_principal_type="SocialIdp",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 0

    def test_null_owner_in_scope(self):
        """SP with null appOwnerOrganizationId is in scope."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Unknown Owner App",
                    app_id=app_id,
                    app_owner_organization_id=None,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_legacy_type_in_scope(self):
        """Legacy service principal type is in scope."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Legacy App",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Legacy",
                    account_enabled=True,
                    app_role_assignment_required=True,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_legacy_type_fail(self):
        """Legacy service principal type with assignment not required: FAIL."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Legacy App",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Legacy",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_indeterminate_assignment_manual(self):
        """SP with app_role_assignment_required=None: MANUAL."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Unknown State App",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=None,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "indeterminate" in result[0].status_extended

    def test_excluded_app_id_config(self):
        """Apps in the exclusion config list are skipped."""
        sp_id = str(uuid4())
        excluded_app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Intranet Portal",
                    app_id=excluded_app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )
        client.audit_config = {
            "entra_assignment_required_excluded_app_ids": [excluded_app_id],
        }

        result = self._run_check(client)

        assert len(result) == 0

    def test_excluded_app_id_config_none(self):
        """When the exclusion config key is None, it is treated as empty."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Some App",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )
        client.audit_config = {
            "entra_assignment_required_excluded_app_ids": None,
        }

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_resource_name_uses_display_name(self):
        """resource_name uses the SP display name."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="My App Display Name",
                    app_id=app_id,
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=True,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_name == "My App Display Name"
        assert result[0].resource_id == sp_id

    def test_multiple_sps_mixed_results(self):
        """Multiple service principals with mixed states produce correct results."""
        sp_pass_id = str(uuid4())
        sp_fail_id = str(uuid4())
        sp_disabled_id = str(uuid4())
        sp_ms_id = str(uuid4())

        client = self._make_client(
            enterprise_apps={
                sp_pass_id: ServicePrincipal(
                    id=sp_pass_id,
                    name="Good App",
                    app_id=str(uuid4()),
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=True,
                ),
                sp_fail_id: ServicePrincipal(
                    id=sp_fail_id,
                    name="Bad App",
                    app_id=str(uuid4()),
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
                sp_disabled_id: ServicePrincipal(
                    id=sp_disabled_id,
                    name="Disabled App",
                    app_id=str(uuid4()),
                    app_owner_organization_id=THIRD_PARTY_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=False,
                    app_role_assignment_required=False,
                ),
                sp_ms_id: ServicePrincipal(
                    id=sp_ms_id,
                    name="MS App",
                    app_id=str(uuid4()),
                    app_owner_organization_id=MICROSOFT_TENANT_ID,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        # 3 findings: Good App (PASS), Bad App (FAIL), Disabled App (PASS).
        # MS App is excluded.
        assert len(result) == 3
        statuses = {r.resource_id: r.status for r in result}
        assert statuses[sp_pass_id] == "PASS"
        assert statuses[sp_fail_id] == "FAIL"
        assert statuses[sp_disabled_id] == "PASS"
        assert sp_ms_id not in statuses

    def test_multiple_excluded_types_no_findings(self):
        """A mix of only excluded types (ManagedIdentity, SocialIdp, MS first-party) yields no findings."""
        client = self._make_client(
            enterprise_apps={
                str(uuid4()): ServicePrincipal(
                    id=str(uuid4()),
                    name="MI 1",
                    app_id=str(uuid4()),
                    service_principal_type="ManagedIdentity",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
                str(uuid4()): ServicePrincipal(
                    id=str(uuid4()),
                    name="Social IDP",
                    app_id=str(uuid4()),
                    service_principal_type="SocialIdp",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
                str(uuid4()): ServicePrincipal(
                    id=str(uuid4()),
                    name="MS First Party",
                    app_id=str(uuid4()),
                    app_owner_organization_id=MICROSOFT_TENANT_ID_2,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 0

    def test_own_tenant_app_in_scope(self):
        """An app owned by the audited tenant (non-Microsoft) is in scope, matching Maester MT.1075 behavior."""
        sp_id = str(uuid4())
        app_id = str(uuid4())
        own_tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        client = self._make_client(
            enterprise_apps={
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="Our Internal App",
                    app_id=app_id,
                    app_owner_organization_id=own_tenant_id,
                    service_principal_type="Application",
                    account_enabled=True,
                    app_role_assignment_required=False,
                ),
            }
        )

        result = self._run_check(client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == sp_id
