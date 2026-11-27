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
    "entra_access_package_catalog_no_unused_resources."
    "entra_access_package_catalog_no_unused_resources"
)


def _resource(origin_id, name="Resource"):
    return AccessPackageResource(
        id=f"res-{origin_id}",
        display_name=name,
        origin_id=origin_id,
        origin_system="AadGroup",
    )


def _package(scope_origin_ids, error=None):
    return AccessPackage(
        id="ap-1",
        display_name="Package",
        catalog_id="cat-1",
        resource_role_scopes=(
            None
            if error
            else [
                AccessPackageResourceRoleScope(
                    role_origin_id="Member",
                    scope_origin_id=origin_id,
                    scope_origin_system="AadGroup",
                )
                for origin_id in scope_origin_ids
            ]
        ),
        resource_role_scopes_error=error,
    )


def _catalog(resources=None, packages=None, resources_error=None, packages_error=None):
    return AccessPackageCatalog(
        id="cat-1",
        display_name="Catalog",
        catalog_type="userManaged",
        state="published",
        resources=resources,
        resources_error=resources_error,
        access_packages=packages,
        access_packages_error=packages_error,
    )


def _run(catalogs, error=None):
    entra_client = mock.MagicMock()
    entra_client.audited_domain = DOMAIN
    entra_client.access_package_catalogs = catalogs
    entra_client.entitlement_management_error = error
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_m365_provider(),
        ),
        mock.patch(f"{CHECK_MODULE}.entra_client", new=entra_client),
    ):
        from prowler.providers.m365.services.entra.entra_access_package_catalog_no_unused_resources.entra_access_package_catalog_no_unused_resources import (
            entra_access_package_catalog_no_unused_resources,
        )

        return entra_access_package_catalog_no_unused_resources().execute()


class Test_entra_access_package_catalog_no_unused_resources:
    def test_catalogs_unreadable_manual(self):
        result = _run(None, error="ODataError: Forbidden")
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "Forbidden" in result[0].status_extended

    def test_no_catalogs_no_findings(self):
        assert _run([]) == []

    def test_catalog_without_resources_pass(self):
        result = _run([_catalog(resources=[], packages=[])])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "has no resources" in result[0].status_extended

    def test_all_resources_used_pass(self):
        result = _run(
            [_catalog(resources=[_resource("g-1")], packages=[_package(["g-1"])])]
        )
        assert result[0].status == "PASS"

    def test_unused_resource_fail(self):
        result = _run(
            [
                _catalog(
                    resources=[_resource("g-1"), _resource("g-2", "Unused Group")],
                    packages=[_package(["g-1"])],
                )
            ]
        )
        assert result[0].status == "FAIL"
        assert "Unused Group" in result[0].status_extended
        assert "g-2" in result[0].status_extended

    def test_resources_without_packages_fail(self):
        result = _run([_catalog(resources=[_resource("g-1")], packages=[])])
        assert result[0].status == "FAIL"

    def test_origin_id_matching_is_case_insensitive(self):
        result = _run(
            [_catalog(resources=[_resource("ABC-1")], packages=[_package(["abc-1"])])]
        )
        assert result[0].status == "PASS"

    def test_resources_error_manual(self):
        result = _run([_catalog(resources_error="ODataError: throttled")])
        assert result[0].status == "MANUAL"
        assert "throttled" in result[0].status_extended

    def test_access_packages_error_manual(self):
        result = _run(
            [_catalog(resources=[_resource("g-1")], packages_error="ODataError: 503")]
        )
        assert result[0].status == "MANUAL"
        assert "503" in result[0].status_extended

    def test_role_scopes_error_manual(self):
        result = _run(
            [
                _catalog(
                    resources=[_resource("g-1")],
                    packages=[_package([], error="ODataError: 500")],
                )
            ]
        )
        assert result[0].status == "MANUAL"
        assert "resourceRoleScopes could not be read" in result[0].status_extended
