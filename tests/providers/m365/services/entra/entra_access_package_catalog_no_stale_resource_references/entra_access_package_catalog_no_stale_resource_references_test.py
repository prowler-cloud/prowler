"""Tests for entra_access_package_catalog_no_stale_resource_references check."""

from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    AccessPackage,
    AccessPackageCatalog,
    AccessPackageResource,
    AccessPackageResourceRoleScope,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider

CHECK_MODULE = (
    "prowler.providers.m365.services.entra."
    "entra_access_package_catalog_no_stale_resource_references."
    "entra_access_package_catalog_no_stale_resource_references.entra_client"
)


def _entra_client_mock():
    """Build a mock entra_client with default attributes."""
    client = mock.MagicMock()
    client.audited_tenant = "audited_tenant"
    client.audited_domain = DOMAIN
    client.access_package_catalogs = []
    client.catalog_group_exists = {}
    client.catalog_sp_app_roles = {}
    client.catalog_errored_ids = set()
    return client


def _catalog(
    catalog_id="cat-1",
    display_name="Test Catalog",
    resources=None,
    resources_error=None,
    access_packages=None,
    access_packages_error=None,
):
    """Build an AccessPackageCatalog test fixture."""
    return AccessPackageCatalog(
        id=catalog_id,
        display_name=display_name,
        catalog_type="userManaged",
        state="published",
        resources=resources,
        resources_error=resources_error,
        access_packages=access_packages,
        access_packages_error=access_packages_error,
    )


def _resource(origin_id="group-1", display_name="Test Group", origin_system="AadGroup"):
    """Build an AccessPackageResource test fixture."""
    return AccessPackageResource(
        id=f"res-{origin_id}",
        display_name=display_name,
        origin_id=origin_id,
        origin_system=origin_system,
    )


def _package(
    pkg_id="pkg-1",
    display_name="Test Package",
    catalog_id="cat-1",
    role_scopes=None,
    role_scopes_error=None,
):
    """Build an AccessPackage test fixture."""
    return AccessPackage(
        id=pkg_id,
        display_name=display_name,
        catalog_id=catalog_id,
        resource_role_scopes=role_scopes,
        resource_role_scopes_error=role_scopes_error,
    )


def _role_scope(
    role_origin_id="role-1",
    role_display_name="admin",
    role_origin_system="AadApplication",
    scope_origin_id="sp-1",
    scope_origin_system="AadApplication",
):
    """Build an AccessPackageResourceRoleScope test fixture."""
    return AccessPackageResourceRoleScope(
        role_origin_id=role_origin_id,
        role_display_name=role_display_name,
        role_origin_system=role_origin_system,
        scope_origin_id=scope_origin_id,
        scope_origin_system=scope_origin_system,
    )


class Test_entra_access_package_catalog_no_stale_resource_references:
    """Tests for the access package catalog stale resource references check."""

    def _run(self, entra_client):
        """Execute the check with the provided mock entra_client."""
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(CHECK_MODULE, new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_access_package_catalog_no_stale_resource_references.entra_access_package_catalog_no_stale_resource_references import (
                entra_access_package_catalog_no_stale_resource_references,
            )

            return entra_access_package_catalog_no_stale_resource_references().execute()

    # ------------------------------------------------------------------
    # Tenant-level / no-resource scenarios
    # ------------------------------------------------------------------

    def test_catalogs_none_returns_manual(self):
        """Tenant-level MANUAL when catalogs could not be read."""
        client = _entra_client_mock()
        client.access_package_catalogs = None
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "entitlementManagement"
        assert result[0].resource_name == "Entitlement management"
        assert "EntitlementManagement.Read.All" in result[0].status_extended
        assert "Entra ID P2" in result[0].status_extended

    def test_no_catalogs_returns_empty(self):
        """No findings when no catalogs exist (len(results) == 0)."""
        client = _entra_client_mock()
        client.access_package_catalogs = []
        result = self._run(client)
        assert len(result) == 0

    def test_catalog_no_resources_passes(self):
        """PASS when catalog has no resources and no access packages."""
        client = _entra_client_mock()
        client.access_package_catalogs = [_catalog(resources=[], access_packages=[])]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "cat-1"
        assert "contains no resources" in result[0].status_extended

    def test_catalog_none_resources_none_packages_passes(self):
        """PASS when catalog has None resources and None access packages."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(resources=None, access_packages=None)
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "contains no resources" in result[0].status_extended

    # ------------------------------------------------------------------
    # PASS scenarios
    # ------------------------------------------------------------------

    def test_all_references_valid_passes(self):
        """PASS when all group and SP references are valid."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Finance Group", "AadGroup"),
                    _resource("sp-1", "My App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="role-1",
                                role_display_name="admin",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": True}
        client.catalog_sp_app_roles = {"sp-1": [{"id": "role-1", "isEnabled": True}]}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_name == "Test Catalog"
        assert "contains no stale resource references" in result[0].status_extended

    def test_catalog_with_resources_but_no_packages_passes(self):
        """PASS when catalog has valid resources but no access packages."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Good Group", "AadGroup"),
                ],
                access_packages=[],
            )
        ]
        client.catalog_group_exists = {"group-1": True}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "contains no stale resource references" in result[0].status_extended

    def test_default_app_role_skipped(self):
        """PASS when role is the default app role (all-zero GUID)."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "My App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="00000000-0000-0000-0000-000000000000",
                                role_display_name="Default Access",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {"sp-1": []}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_default_access_display_name_skipped(self):
        """PASS when role display name is 'Default Access' even with non-zero ID."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "My App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="some-non-zero-id",
                                role_display_name="Default Access",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {"sp-1": []}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_group_membership_role_member_skipped(self):
        """PASS when role is a group membership role (Member_ prefix)."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "My Group", "AadGroup"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="Member_group-1",
                                role_display_name="Member",
                                role_origin_system="AadGroup",
                                scope_origin_id="group-1",
                                scope_origin_system="AadGroup",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": True}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_group_ownership_role_owner_skipped(self):
        """PASS when role is a group ownership role (Owner_ prefix)."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "My Group", "AadGroup"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="Owner_group-1",
                                role_display_name="Owner",
                                role_origin_system="AadGroup",
                                scope_origin_id="group-1",
                                scope_origin_system="AadGroup",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": True}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_sharepoint_resources_ignored(self):
        """SharePoint resources are not evaluated."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-site-1", "SharePoint Site", "SharePointOnline"),
                ],
            )
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_unknown_origin_system_ignored(self):
        """Resources with an unknown originSystem are not evaluated."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("custom-1", "Custom Resource", "CustomConnectedApp"),
                ],
            )
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_package_with_empty_role_scopes_passes(self):
        """PASS when access package has an empty role scopes list."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(role_scopes=[]),
                ],
            )
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_package_with_none_role_scopes_passes(self):
        """PASS when access package has None role scopes (no error)."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(role_scopes=None, role_scopes_error=None),
                ],
            )
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    # ------------------------------------------------------------------
    # FAIL scenarios
    # ------------------------------------------------------------------

    def test_deleted_group_fails(self):
        """FAIL when a group resource is confirmed deleted (404)."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Old Group", "AadGroup"),
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": False}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "deleted group" in result[0].status_extended
        assert "Old Group" in result[0].status_extended
        assert "group-1" in result[0].status_extended
        assert "1 stale reference(s)" in result[0].status_extended

    def test_deleted_service_principal_fails(self):
        """FAIL when a service principal resource is confirmed deleted (404)."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "Deleted App", "AadApplication"),
                ],
            )
        ]
        client.catalog_sp_app_roles = {"sp-1": None}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "deleted service principal" in result[0].status_extended
        assert "Deleted App" in result[0].status_extended
        assert "sp-1" in result[0].status_extended

    def test_removed_app_role_fails(self):
        """FAIL when an app role no longer exists on the service principal."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "My App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="missing-role",
                                role_display_name="Gone Role",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {
            "sp-1": [{"id": "other-role", "isEnabled": True}]
        }
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "removed app role" in result[0].status_extended
        assert "Gone Role" in result[0].status_extended
        assert "missing-role" in result[0].status_extended
        assert "Test Package" in result[0].status_extended

    def test_disabled_app_role_fails(self):
        """FAIL when an app role exists but is disabled."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "My App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="role-1",
                                role_display_name="Disabled Role",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {"sp-1": [{"id": "role-1", "isEnabled": False}]}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "disabled app role" in result[0].status_extended
        assert "Disabled Role" in result[0].status_extended

    def test_deleted_group_scope_in_role_scope_fails(self):
        """FAIL when a group scope in an access package role scope is deleted."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="Member_group-1",
                                role_display_name="Member",
                                role_origin_system="AadGroup",
                                scope_origin_id="group-1",
                                scope_origin_system="AadGroup",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": False}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "deleted group scope" in result[0].status_extended
        assert "group-1" in result[0].status_extended

    def test_deleted_sp_scope_in_role_scope_fails(self):
        """FAIL when an SP scope in an access package role scope is deleted."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="role-1",
                                role_display_name="admin",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {"sp-1": None}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "deleted service principal scope" in result[0].status_extended
        assert "sp-1" in result[0].status_extended

    def test_multiple_stale_items_in_one_catalog(self):
        """FAIL listing all stale items when multiple references are broken."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Dead Group", "AadGroup"),
                    _resource("sp-1", "Dead App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="missing-role",
                                role_display_name="Gone Role",
                                scope_origin_id="sp-2",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": False}
        client.catalog_sp_app_roles = {
            "sp-1": None,
            "sp-2": [{"id": "other", "isEnabled": True}],
        }
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "3 stale reference(s)" in result[0].status_extended
        assert "deleted group" in result[0].status_extended
        assert "deleted service principal" in result[0].status_extended
        assert "removed app role" in result[0].status_extended

    def test_duplicate_stale_references_deduplicated(self):
        """Stale items are deduplicated across resources and role scopes."""
        client = _entra_client_mock()
        # Same group referenced as both a catalog resource and a role scope
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Dead Group", "AadGroup"),
                ],
                access_packages=[
                    _package(
                        pkg_id="pkg-1",
                        display_name="Package A",
                        role_scopes=[
                            _role_scope(
                                role_origin_id="Member_group-1",
                                role_display_name="Member",
                                role_origin_system="AadGroup",
                                scope_origin_id="group-1",
                                scope_origin_system="AadGroup",
                            ),
                        ],
                    ),
                    _package(
                        pkg_id="pkg-2",
                        display_name="Package B",
                        role_scopes=[
                            _role_scope(
                                role_origin_id="Member_group-1",
                                role_display_name="Member",
                                role_origin_system="AadGroup",
                                scope_origin_id="group-1",
                                scope_origin_system="AadGroup",
                            ),
                        ],
                    ),
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": False}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        # The deleted group resource + deduplicated group scope references
        # The catalog resource creates "deleted group 'Dead Group' (group-1)"
        # Both packages create "deleted group scope (group-1) in access package '...'"
        # but each package name differs so they are distinct stale items
        assert "deleted group" in result[0].status_extended

    # ------------------------------------------------------------------
    # MANUAL scenarios
    # ------------------------------------------------------------------

    def test_errored_group_lookup_manual(self):
        """MANUAL when group lookup failed with non-404 error."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Errored Group", "AadGroup"),
                ],
            )
        ]
        client.catalog_errored_ids = {"group-1"}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be verified" in result[0].status_extended
        assert "Errored Group" in result[0].status_extended

    def test_errored_sp_lookup_manual(self):
        """MANUAL when SP lookup failed with non-404 error."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "Errored App", "AadApplication"),
                ],
            )
        ]
        client.catalog_errored_ids = {"sp-1"}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be verified" in result[0].status_extended
        assert "Errored App" in result[0].status_extended

    def test_errored_group_scope_in_role_scope_manual(self):
        """MANUAL when a group scope lookup in a role scope errored."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="Member_group-1",
                                role_display_name="Member",
                                role_origin_system="AadGroup",
                                scope_origin_id="group-1",
                                scope_origin_system="AadGroup",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_errored_ids = {"group-1"}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be verified" in result[0].status_extended
        assert "group-1" in result[0].status_extended

    def test_errored_sp_scope_in_role_scope_manual(self):
        """MANUAL when an SP scope lookup in a role scope errored."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="role-1",
                                role_display_name="admin",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_errored_ids = {"sp-1"}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be verified" in result[0].status_extended
        assert "sp-1" in result[0].status_extended

    def test_resources_error_manual(self):
        """MANUAL when catalog resources could not be read."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(resources_error="SomeError: 403 Forbidden")
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "catalog resources could not be read" in result[0].status_extended
        assert "403 Forbidden" in result[0].status_extended

    def test_access_packages_error_manual(self):
        """MANUAL when access packages could not be read."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages_error="SomeError: 403",
            )
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "access packages could not be read" in result[0].status_extended

    def test_role_scopes_error_manual(self):
        """MANUAL when access package role scopes could not be read."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(role_scopes_error="SomeError: timeout"),
                ],
            )
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "resourceRoleScopes" in result[0].status_extended
        assert "Test Package" in result[0].status_extended

    # ------------------------------------------------------------------
    # Precedence / mixed scenarios
    # ------------------------------------------------------------------

    def test_fail_takes_precedence_over_manual(self):
        """FAIL takes precedence when both stale and unverified items exist."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Deleted Group", "AadGroup"),
                    _resource("group-2", "Errored Group", "AadGroup"),
                ],
            )
        ]
        client.catalog_group_exists = {"group-1": False}
        client.catalog_errored_ids = {"group-2"}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "deleted group" in result[0].status_extended
        assert "could not be verified" in result[0].status_extended
        assert "Additionally" in result[0].status_extended

    def test_fail_with_resources_error_and_stale_reference(self):
        """FAIL when resources error exists but a stale reference is confirmed."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-1", "Dead Group", "AadGroup"),
                ],
                access_packages_error="SomeError: throttled",
            )
        ]
        client.catalog_group_exists = {"group-1": False}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "deleted group" in result[0].status_extended
        assert "access packages could not be read" in result[0].status_extended

    # ------------------------------------------------------------------
    # Multiple catalogs
    # ------------------------------------------------------------------

    def test_multiple_catalogs(self):
        """Multiple catalogs produce one finding each."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                catalog_id="cat-1",
                display_name="Clean Catalog",
                resources=[
                    _resource("group-1", "Good Group", "AadGroup"),
                ],
            ),
            _catalog(
                catalog_id="cat-2",
                display_name="Stale Catalog",
                resources=[
                    _resource("group-2", "Dead Group", "AadGroup"),
                ],
            ),
        ]
        client.catalog_group_exists = {"group-1": True, "group-2": False}
        result = self._run(client)
        assert len(result) == 2
        assert result[0].status == "PASS"
        assert result[0].resource_id == "cat-1"
        assert result[0].resource_name == "Clean Catalog"
        assert result[1].status == "FAIL"
        assert result[1].resource_id == "cat-2"
        assert result[1].resource_name == "Stale Catalog"

    def test_multiple_catalogs_mixed_statuses(self):
        """Three catalogs: PASS, FAIL, MANUAL — one finding each."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                catalog_id="cat-pass",
                display_name="OK Catalog",
                resources=[
                    _resource("group-ok", "Exists Group", "AadGroup"),
                ],
            ),
            _catalog(
                catalog_id="cat-fail",
                display_name="Broken Catalog",
                resources=[
                    _resource("group-dead", "Gone Group", "AadGroup"),
                ],
            ),
            _catalog(
                catalog_id="cat-manual",
                display_name="Uncertain Catalog",
                resources=[
                    _resource("group-err", "Mystery Group", "AadGroup"),
                ],
            ),
        ]
        client.catalog_group_exists = {"group-ok": True, "group-dead": False}
        client.catalog_errored_ids = {"group-err"}
        result = self._run(client)
        assert len(result) == 3
        assert result[0].status == "PASS"
        assert result[0].resource_id == "cat-pass"
        assert result[1].status == "FAIL"
        assert result[1].resource_id == "cat-fail"
        assert result[2].status == "MANUAL"
        assert result[2].resource_id == "cat-manual"

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    def test_catalog_display_name_fallback_to_id(self):
        """resource_name falls back to catalog id when display_name is empty."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                catalog_id="cat-no-name",
                display_name="",
                resources=[],
                access_packages=[],
            )
        ]
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_name == "cat-no-name"
        assert "cat-no-name" in result[0].status_extended

    def test_sp_not_in_lookup_maps_not_flagged(self):
        """SP origin_id not present in sp_app_roles at all is not flagged.

        If the service did not look up the SP (e.g. it wasn't referenced by
        any AadApplication resource or scope), it should not be treated as
        deleted.
        """
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-unknown", "Unknown App", "AadApplication"),
                ],
            )
        ]
        # sp-unknown is NOT in sp_app_roles at all (not looked up)
        client.catalog_sp_app_roles = {}
        result = self._run(client)
        assert len(result) == 1
        # Not in the map means it wasn't looked up -> not confirmed deleted
        assert result[0].status == "PASS"

    def test_group_not_in_lookup_map_not_flagged(self):
        """Group origin_id not in group_exists map is not flagged as deleted."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("group-unknown", "Unknown Group", "AadGroup"),
                ],
            )
        ]
        # group-unknown is NOT in group_exists (not looked up)
        client.catalog_group_exists = {}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_sp_exists_with_empty_app_roles_and_non_default_role(self):
        """FAIL when SP exists but has empty appRoles and a non-default role is granted."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "My App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="custom-role-id",
                                role_display_name="Custom Role",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {"sp-1": []}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "removed app role" in result[0].status_extended
        assert "Custom Role" in result[0].status_extended

    def test_app_role_not_validated_when_sp_deleted(self):
        """App role is not validated when the SP itself is deleted.

        If the SP is confirmed deleted (None in sp_app_roles), the role
        should not be separately flagged — only the deleted SP scope is
        reported.
        """
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="some-role",
                                role_display_name="Some Role",
                                scope_origin_id="sp-deleted",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {"sp-deleted": None}
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "deleted service principal scope" in result[0].status_extended
        # Should NOT also report the role as removed
        assert "removed app role" not in result[0].status_extended

    def test_multiple_roles_on_same_sp_mixed_valid_and_stale(self):
        """One valid and one removed role on the same SP — FAIL for removed only."""
        client = _entra_client_mock()
        client.access_package_catalogs = [
            _catalog(
                resources=[
                    _resource("sp-1", "My App", "AadApplication"),
                ],
                access_packages=[
                    _package(
                        role_scopes=[
                            _role_scope(
                                role_origin_id="valid-role",
                                role_display_name="Valid Role",
                                scope_origin_id="sp-1",
                            ),
                            _role_scope(
                                role_origin_id="stale-role",
                                role_display_name="Stale Role",
                                scope_origin_id="sp-1",
                            ),
                        ],
                    )
                ],
            )
        ]
        client.catalog_sp_app_roles = {
            "sp-1": [{"id": "valid-role", "isEnabled": True}]
        }
        result = self._run(client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "removed app role" in result[0].status_extended
        assert "Stale Role" in result[0].status_extended
        assert "Valid Role" not in result[0].status_extended
