from unittest import mock
from uuid import uuid4

from prowler.providers.m365.services.entra.entra_service import ServicePrincipal
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

EXCHANGE_ADMIN_ROLE = "29232cdf-9323-42fd-ade2-1d097af3e4de"
SHAREPOINT_ADMIN_ROLE = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_service_principal_privileged_permissions_no_owners."
    "entra_service_principal_privileged_permissions_no_owners"
)


def _mock_entra_client():
    """Return a MagicMock pre-configured with common attributes."""
    entra_client = mock.MagicMock()
    entra_client.audited_tenant = "audited_tenant"
    entra_client.audited_domain = DOMAIN
    entra_client.tenant_domain = DOMAIN
    entra_client.privileged_permission_service_principals = {}
    entra_client.privileged_permission_service_principals_error = None
    return entra_client


class Test_entra_service_principal_privileged_permissions_no_owners:
    """Tests for entra_service_principal_privileged_permissions_no_owners."""

    def test_no_privileged_service_principals(self):
        """No privileged service principals: expected no findings."""
        entra_client = _mock_entra_client()

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 0

    def test_error_retrieving_data(self):
        """Service layer error: expected MANUAL finding."""
        entra_client = _mock_entra_client()
        entra_client.privileged_permission_service_principals_error = (
            "ODataError: Insufficient privileges"
        )

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == DOMAIN
            assert result[0].resource_name == "Service Principals"
            assert "Cannot evaluate" in result[0].status_extended
            assert "ODataError: Insufficient privileges" in result[0].status_extended
            assert "Directory.Read.All" in result[0].status_extended

    def test_privileged_app_permissions_with_sp_owners_pass(self):
        """SP with privileged app permissions and SP owners: expected PASS."""
        entra_client = _mock_entra_client()
        sp_id = str(uuid4())
        owner_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="OwnedPrivApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Directory.ReadWrite.All"],
                    sp_owner_ids=[owner_id],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == sp_id
            assert result[0].resource_name == "OwnedPrivApp"
            assert "1 owner(s)" in result[0].status_extended
            assert "1 on the service principal" in result[0].status_extended
            assert "0 on the parent app registration" in result[0].status_extended
            assert "Directory.ReadWrite.All" in result[0].status_extended

    def test_privileged_app_permissions_no_owners_fail(self):
        """SP with privileged app permissions and no owners: expected FAIL."""
        entra_client = _mock_entra_client()
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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="OrphanedApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=[
                        "Directory.ReadWrite.All",
                        "Mail.Send",
                    ],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == sp_id
            assert result[0].resource_name == "OrphanedApp"
            assert "no owners" in result[0].status_extended
            assert "Directory.ReadWrite.All" in result[0].status_extended
            assert "Mail.Send" in result[0].status_extended

    def test_privileged_delegated_permissions_no_owners_fail(self):
        """SP with admin-consented delegated permissions and no owners: expected FAIL."""
        entra_client = _mock_entra_client()
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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="DelegatedApp",
                    app_id=str(uuid4()),
                    privileged_delegated_permissions=[
                        "User.ReadWrite.All",
                    ],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == sp_id
            assert "User.ReadWrite.All" in result[0].status_extended
            assert "no owners" in result[0].status_extended

    def test_privileged_directory_role_no_owners_fail(self):
        """SP with non-Tier-0 privileged role and no owners: expected FAIL."""
        entra_client = _mock_entra_client()
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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="RoleApp",
                    app_id=str(uuid4()),
                    privileged_directory_role_ids=[EXCHANGE_ADMIN_ROLE],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == sp_id
            assert "Exchange Administrator" in result[0].status_extended
            assert "no owners" in result[0].status_extended

    def test_privileged_permissions_with_app_owners_only_pass(self):
        """SP with privileged permissions and owners only on parent app: expected PASS."""
        entra_client = _mock_entra_client()
        sp_id = str(uuid4())
        app_owner_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="AppRegOwnedApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Application.ReadWrite.All"],
                    sp_owner_ids=[],
                    app_owner_ids=[app_owner_id],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "1 owner(s)" in result[0].status_extended
            assert "0 on the service principal" in result[0].status_extended
            assert "1 on the parent app registration" in result[0].status_extended

    def test_same_owner_on_sp_and_app_deduplication_pass(self):
        """Same principal owns both SP and app: unique owner count is deduplicated."""
        entra_client = _mock_entra_client()
        sp_id = str(uuid4())
        shared_owner_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="DualOwnedApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Directory.ReadWrite.All"],
                    sp_owner_ids=[shared_owner_id],
                    app_owner_ids=[shared_owner_id],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == sp_id
            # Unique owners = 1, but counts per source are each 1
            assert "1 owner(s)" in result[0].status_extended
            assert "1 on the service principal" in result[0].status_extended
            assert "1 on the parent app registration" in result[0].status_extended

    def test_both_sp_and_app_owners_distinct_pass(self):
        """SP with distinct owners on both SP and app: expected PASS with correct counts."""
        entra_client = _mock_entra_client()
        sp_id = str(uuid4())
        sp_owner_id = str(uuid4())
        app_owner_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="WellOwnedApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Mail.Send"],
                    sp_owner_ids=[sp_owner_id],
                    app_owner_ids=[app_owner_id],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "2 owner(s)" in result[0].status_extended
            assert "1 on the service principal" in result[0].status_extended
            assert "1 on the parent app registration" in result[0].status_extended

    def test_all_three_permission_types_combined_no_owners_fail(self):
        """SP with app, delegated, and directory role permissions and no owners: expected FAIL."""
        entra_client = _mock_entra_client()
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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="OverPrivilegedApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Directory.ReadWrite.All"],
                    privileged_delegated_permissions=["User.ReadWrite.All"],
                    privileged_directory_role_ids=[EXCHANGE_ADMIN_ROLE],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == sp_id
            assert "no owners" in result[0].status_extended
            # All three permission types should appear in status_extended
            assert "Directory.ReadWrite.All" in result[0].status_extended
            assert "User.ReadWrite.All" in result[0].status_extended
            assert "Exchange Administrator" in result[0].status_extended

    def test_unknown_role_id_falls_back_to_raw_id(self):
        """Directory role ID not in mapping: raw ID appears in status_extended."""
        entra_client = _mock_entra_client()
        sp_id = str(uuid4())
        unknown_role_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="UnknownRoleApp",
                    app_id=str(uuid4()),
                    privileged_directory_role_ids=[unknown_role_id],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Falls back to raw role ID when not in mapping
            assert unknown_role_id in result[0].status_extended

    def test_sp_with_empty_permissions_skipped(self):
        """Defensive: SP in dict with all empty permission lists is skipped."""
        entra_client = _mock_entra_client()
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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="NoPrivsApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=[],
                    privileged_delegated_permissions=[],
                    privileged_directory_role_ids=[],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 0

    def test_multiple_sps_mixed_results(self):
        """Multiple SPs with different states: expected mixed PASS and FAIL."""
        entra_client = _mock_entra_client()
        sp_id_owned = str(uuid4())
        sp_id_orphaned = str(uuid4())
        owner_id = str(uuid4())

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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id_owned: ServicePrincipal(
                    id=sp_id_owned,
                    name="OwnedApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Mail.Send"],
                    sp_owner_ids=[owner_id],
                    app_owner_ids=[],
                ),
                sp_id_orphaned: ServicePrincipal(
                    id=sp_id_orphaned,
                    name="OrphanedApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Files.ReadWrite.All"],
                    privileged_delegated_permissions=["Group.ReadWrite.All"],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                ),
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 2
            results_by_id = {r.resource_id: r for r in result}
            assert results_by_id[sp_id_owned].status == "PASS"
            assert results_by_id[sp_id_owned].resource_name == "OwnedApp"
            assert results_by_id[sp_id_orphaned].status == "FAIL"
            assert results_by_id[sp_id_orphaned].resource_name == "OrphanedApp"
            assert (
                "Files.ReadWrite.All" in results_by_id[sp_id_orphaned].status_extended
            )
            assert (
                "Group.ReadWrite.All" in results_by_id[sp_id_orphaned].status_extended
            )

    def test_permissions_are_sorted_and_deduplicated_in_label(self):
        """Duplicate permission names across sources produce a deduplicated, sorted label."""
        entra_client = _mock_entra_client()
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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="DupPermApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=[
                        "Mail.Send",
                        "Directory.ReadWrite.All",
                    ],
                    privileged_delegated_permissions=[
                        "Mail.Send",
                    ],
                    sp_owner_ids=[],
                    app_owner_ids=[],
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # The check uses sorted(set(...)) so duplicates are removed and sorted
            assert "Directory.ReadWrite.All, Mail.Send" in result[0].status_extended

    def test_lookup_error_manual(self):
        """SP whose permissions or owners could not be read: expected MANUAL."""
        entra_client = _mock_entra_client()
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
            from prowler.providers.m365.services.entra.entra_service_principal_privileged_permissions_no_owners.entra_service_principal_privileged_permissions_no_owners import (
                entra_service_principal_privileged_permissions_no_owners,
            )

            entra_client.privileged_permission_service_principals = {
                sp_id: ServicePrincipal(
                    id=sp_id,
                    name="ThrottledApp",
                    app_id=str(uuid4()),
                    privileged_app_permissions=["Directory.ReadWrite.All"],
                    privileged_permissions_error="service principal owners (ODataError)",
                )
            }

            check = entra_service_principal_privileged_permissions_no_owners()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert result[0].resource_id == sp_id
            assert "service principal owners" in result[0].status_extended
