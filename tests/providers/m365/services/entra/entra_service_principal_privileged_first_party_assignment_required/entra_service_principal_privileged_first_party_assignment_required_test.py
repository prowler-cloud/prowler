"""Tests for entra_service_principal_privileged_first_party_assignment_required check."""

from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import (
    DEFAULT_PRIVILEGED_FIRST_PARTY_APP_IDS,
    ServicePrincipal,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_service_principal_privileged_first_party_assignment_required."
    "entra_service_principal_privileged_first_party_assignment_required"
)

# Use a small subset of app IDs for tests to keep them concise.
TEST_APP_ID = "de8bc8b5-d9f9-48b1-a8ad-b748da725064"  # Graph Explorer
TEST_APP_NAME = "Graph Explorer"
TEST_APP_ID_2 = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI
TEST_APP_NAME_2 = "Microsoft Azure CLI"


class Test_entra_service_principal_privileged_first_party_assignment_required:
    """Tests for the privileged first-party assignment required check."""

    def test_service_principal_exists_assignment_required_true(self):
        """SP exists with appRoleAssignmentRequired=true: expected PASS."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [TEST_APP_ID],
            }
            entra_client.enterprise_apps = {
                TEST_APP_ID: ServicePrincipal(
                    id=sp_id,
                    app_id=TEST_APP_ID,
                    name=TEST_APP_NAME,
                    app_role_assignment_required=True,
                    account_enabled=True,
                ),
            }

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "requires explicit user assignment" in result[0].status_extended
            assert result[0].resource_id == sp_id
            assert result[0].resource_name == TEST_APP_NAME

    def test_service_principal_exists_assignment_required_false_enabled(self):
        """SP exists, enabled, appRoleAssignmentRequired=false: expected FAIL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [TEST_APP_ID],
            }
            entra_client.enterprise_apps = {
                TEST_APP_ID: ServicePrincipal(
                    id=sp_id,
                    app_id=TEST_APP_ID,
                    name=TEST_APP_NAME,
                    app_role_assignment_required=False,
                    account_enabled=True,
                ),
            }

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "open to all users" in result[0].status_extended
            assert result[0].resource_id == sp_id

    def test_service_principal_exists_assignment_required_false_disabled(self):
        """SP exists, disabled, appRoleAssignmentRequired=false: expected FAIL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [TEST_APP_ID],
            }
            entra_client.enterprise_apps = {
                TEST_APP_ID: ServicePrincipal(
                    id=sp_id,
                    app_id=TEST_APP_ID,
                    name=TEST_APP_NAME,
                    app_role_assignment_required=False,
                    account_enabled=False,
                ),
            }

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "disabled but assignment is not required" in result[0].status_extended
            )

    def test_service_principal_missing(self):
        """SP does not exist in tenant: expected FAIL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [TEST_APP_ID],
            }
            entra_client.enterprise_apps = {}

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not exist in the tenant" in result[0].status_extended
            assert result[0].resource_id == TEST_APP_ID
            assert result[0].resource_name == TEST_APP_NAME

    def test_empty_config_falls_back_to_defaults(self):
        """An explicit null app ID list falls back to the default monitored apps."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {"entra_privileged_first_party_app_ids": None}
            entra_client.enterprise_apps = {}

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == len(DEFAULT_PRIVILEGED_FIRST_PARTY_APP_IDS)
            assert all(r.status == "FAIL" for r in result)

    def test_service_principal_assignment_required_null(self):
        """SP exists but appRoleAssignmentRequired is None: expected MANUAL."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [TEST_APP_ID],
            }
            entra_client.enterprise_apps = {
                TEST_APP_ID: ServicePrincipal(
                    id=sp_id,
                    app_id=TEST_APP_ID,
                    name=TEST_APP_NAME,
                    app_role_assignment_required=None,
                    account_enabled=True,
                ),
            }

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "null or missing" in result[0].status_extended

    def test_service_principal_listing_error(self):
        """Service principal listing failed: expected single MANUAL finding."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN
        entra_client.tenant_domain = DOMAIN

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = (
                "ODataError: Authorization_RequestDenied"
            )
            entra_client.enterprise_apps = {}

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "could not be retrieved" in result[0].status_extended
            assert result[0].resource_id == DOMAIN

    def test_multiple_apps_mixed_results(self):
        """Multiple monitored apps with mixed results."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id_1 = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [
                    TEST_APP_ID,
                    TEST_APP_ID_2,
                ],
            }
            # First app exists with assignment required; second is missing.
            entra_client.enterprise_apps = {
                TEST_APP_ID: ServicePrincipal(
                    id=sp_id_1,
                    app_id=TEST_APP_ID,
                    name=TEST_APP_NAME,
                    app_role_assignment_required=True,
                    account_enabled=True,
                ),
            }

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 2

            pass_findings = [r for r in result if r.status == "PASS"]
            fail_findings = [r for r in result if r.status == "FAIL"]

            assert len(pass_findings) == 1
            assert len(fail_findings) == 1

            assert pass_findings[0].resource_name == TEST_APP_NAME
            assert fail_findings[0].resource_name == TEST_APP_NAME_2
            assert "does not exist" in fail_findings[0].status_extended

    def test_case_insensitive_app_id_matching(self):
        """App IDs are matched case-insensitively."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

        sp_id = str(uuid4())
        upper_app_id = TEST_APP_ID.upper()

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            # Config uses uppercase appId.
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [upper_app_id],
            }
            # Lookup dict uses lowercase key (as populated by service method).
            entra_client.enterprise_apps = {
                TEST_APP_ID: ServicePrincipal(
                    id=sp_id,
                    app_id=TEST_APP_ID,
                    name=TEST_APP_NAME,
                    app_role_assignment_required=True,
                    account_enabled=True,
                ),
            }

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_empty_monitored_list(self):
        """Empty monitored app list: expected no findings."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {
                "entra_privileged_first_party_app_ids": [],
            }
            entra_client.enterprise_apps = {}

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            assert len(result) == 0

    def test_default_app_ids_used_when_config_missing(self):
        """When audit_config has no key, default app IDs are used."""
        entra_client = mock.MagicMock()
        entra_client.audited_tenant = "audited_tenant"
        entra_client.audited_domain = DOMAIN

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_first_party_assignment_required.entra_service_principal_privileged_first_party_assignment_required import (
                entra_service_principal_privileged_first_party_assignment_required,
            )

            entra_client.enterprise_apps_error = None
            entra_client.audit_config = {}  # No key present
            entra_client.enterprise_apps = {}

            check = entra_service_principal_privileged_first_party_assignment_required()
            result = check.execute()

            # Should produce one FAIL finding per default monitored app.
            assert len(result) == len(DEFAULT_PRIVILEGED_FIRST_PARTY_APP_IDS)
            for finding in result:
                assert finding.status == "FAIL"
                assert "does not exist" in finding.status_extended
