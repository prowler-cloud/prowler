"""Check that access package catalogs contain no stale resource references."""

from typing import Dict, List, Optional, Set

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# Default app role that is never present in servicePrincipal.appRoles.
_DEFAULT_ROLE_ID = "00000000-0000-0000-0000-000000000000"
_DEFAULT_ROLE_DISPLAY_NAME = "Default Access"


class entra_access_package_catalog_no_stale_resource_references(Check):
    """Ensure access package catalogs contain no stale resource references.

    Every Entra ID Governance access package catalog should only contain
    resources (groups, applications) and access package role scopes that
    still exist in the directory. Stale references indicate deleted groups,
    removed service principals, or disabled/removed app roles, which cause
    access packages to grant access that is never actually provisioned.

    - PASS: All AadGroup and AadApplication references resolve, and every
      app role granted by the catalog's access packages exists and is enabled.
    - FAIL: At least one group or service principal is confirmed deleted
      (HTTP 404), or an app role is missing or disabled.
    - MANUAL: Entitlement management data could not be read (tenant level),
      or a catalog's resources/packages could not be fully verified due to
      non-404 errors.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings: list[CheckReportM365] = []

        # Tenant-level MANUAL: catalogs could not be read at all
        if entra_client.access_package_catalogs is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Entitlement management",
                resource_id="entitlementManagement",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Entitlement management data could not be read "
                f"({entra_client.entitlement_management_error or 'unknown error'}). "
                "Verify that the EntitlementManagement.Read.All permission "
                "is granted to the scanning application and that the tenant "
                "has a Microsoft Entra ID P2 or Entra ID Governance license."
            )
            findings.append(report)
            return findings

        # No catalogs returned: no findings (feature may be unavailable)
        if not entra_client.access_package_catalogs:
            return findings

        group_exists = entra_client.catalog_group_exists
        sp_app_roles = entra_client.catalog_sp_app_roles
        errored_ids = entra_client.catalog_errored_ids

        for catalog in entra_client.access_package_catalogs:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=catalog,
                resource_name=catalog.display_name or catalog.id,
                resource_id=catalog.id,
            )

            stale_items, unverified_parts = self._evaluate_catalog(
                catalog, group_exists, sp_app_roles, errored_ids
            )

            if stale_items:
                report.status = "FAIL"
                report.status_extended = self._format_fail(
                    catalog.display_name or catalog.id,
                    stale_items,
                    unverified_parts,
                )
            elif unverified_parts:
                report.status = "MANUAL"
                report.status_extended = self._format_manual(
                    catalog.display_name or catalog.id,
                    unverified_parts,
                )
            else:
                report.status = "PASS"
                has_resources = (catalog.resources and len(catalog.resources) > 0) or (
                    catalog.access_packages and len(catalog.access_packages) > 0
                )
                if has_resources:
                    report.status_extended = (
                        f"Access package catalog "
                        f"{catalog.display_name or catalog.id} contains no "
                        f"stale resource references."
                    )
                else:
                    report.status_extended = (
                        f"Access package catalog "
                        f"{catalog.display_name or catalog.id} contains no "
                        f"resources."
                    )

            findings.append(report)

        return findings

    @staticmethod
    def _evaluate_catalog(
        catalog,
        group_exists: Dict[str, bool],
        sp_app_roles: Dict[str, Optional[list]],
        errored_ids: Set[str],
    ) -> tuple:
        """Evaluate a single catalog for stale references.

        Args:
            catalog: The AccessPackageCatalog to evaluate.
            group_exists: Map of group origin IDs to existence status.
            sp_app_roles: Map of SP origin IDs to app roles or None if deleted.
            errored_ids: Set of origin IDs whose lookup failed (non-404).

        Returns:
            Tuple of (stale_items, unverified_parts) where stale_items is a
            list of descriptive strings for confirmed stale references and
            unverified_parts is a list of strings describing what could not
            be verified.
        """
        stale_items: List[str] = []
        unverified_parts: List[str] = []

        # Check for read errors on catalog sub-resources
        if catalog.resources_error:
            unverified_parts.append(
                f"catalog resources could not be read ({catalog.resources_error})"
            )
        if catalog.access_packages_error:
            unverified_parts.append(
                f"access packages could not be read ({catalog.access_packages_error})"
            )

        # Validate catalog resources (groups and applications)
        if catalog.resources:
            for resource in catalog.resources:
                if resource.origin_system == "AadGroup":
                    if resource.origin_id in errored_ids:
                        unverified_parts.append(
                            f"group '{resource.display_name}' "
                            f"({resource.origin_id}) could not be verified"
                        )
                    elif group_exists.get(resource.origin_id) is False:
                        stale_items.append(
                            f"deleted group '{resource.display_name}' "
                            f"({resource.origin_id})"
                        )
                elif resource.origin_system == "AadApplication":
                    if resource.origin_id in errored_ids:
                        unverified_parts.append(
                            f"service principal '{resource.display_name}' "
                            f"({resource.origin_id}) could not be verified"
                        )
                    elif sp_app_roles.get(resource.origin_id) is None and (
                        resource.origin_id in sp_app_roles
                    ):
                        stale_items.append(
                            f"deleted service principal "
                            f"'{resource.display_name}' "
                            f"({resource.origin_id})"
                        )

        # Validate access package role scopes
        if catalog.access_packages:
            for pkg in catalog.access_packages:
                if pkg.resource_role_scopes_error:
                    unverified_parts.append(
                        f"resourceRoleScopes of access package "
                        f"'{pkg.display_name}' could not be read "
                        f"({pkg.resource_role_scopes_error})"
                    )
                    continue
                if not pkg.resource_role_scopes:
                    continue
                for rrs in pkg.resource_role_scopes:
                    # Validate scope (the underlying resource)
                    if rrs.scope_origin_system == "AadGroup":
                        if rrs.scope_origin_id in errored_ids:
                            unverified_parts.append(
                                f"group scope '{rrs.scope_origin_id}' in "
                                f"access package '{pkg.display_name}' "
                                f"could not be verified"
                            )
                        elif group_exists.get(rrs.scope_origin_id) is False:
                            stale_items.append(
                                f"deleted group scope "
                                f"({rrs.scope_origin_id}) in access "
                                f"package '{pkg.display_name}'"
                            )
                    elif rrs.scope_origin_system == "AadApplication":
                        if rrs.scope_origin_id in errored_ids:
                            unverified_parts.append(
                                f"service principal scope "
                                f"'{rrs.scope_origin_id}' in access "
                                f"package '{pkg.display_name}' could not "
                                f"be verified"
                            )
                        elif sp_app_roles.get(rrs.scope_origin_id) is None and (
                            rrs.scope_origin_id in sp_app_roles
                        ):
                            stale_items.append(
                                f"deleted service principal scope "
                                f"({rrs.scope_origin_id}) in access "
                                f"package '{pkg.display_name}'"
                            )
                        elif (
                            rrs.role_origin_system == "AadApplication"
                            and rrs.scope_origin_id in sp_app_roles
                            and sp_app_roles[rrs.scope_origin_id] is not None
                        ):
                            # Validate app role if the SP exists
                            _validate_app_role(
                                rrs,
                                pkg.display_name,
                                sp_app_roles[rrs.scope_origin_id],
                                stale_items,
                            )

        # Deduplicate while preserving order
        stale_items = list(dict.fromkeys(stale_items))
        unverified_parts = list(dict.fromkeys(unverified_parts))

        return stale_items, unverified_parts

    @staticmethod
    def _format_fail(
        catalog_name: str,
        stale_items: List[str],
        unverified_parts: List[str],
    ) -> str:
        """Format the FAIL status_extended message.

        Args:
            catalog_name: Display name of the catalog.
            stale_items: List of confirmed stale reference descriptions.
            unverified_parts: List of unverified reference descriptions.

        Returns:
            A human-readable failure message.
        """
        items_str = "; ".join(stale_items)
        msg = (
            f"Access package catalog {catalog_name} has "
            f"{len(stale_items)} stale reference(s): {items_str}."
        )
        if unverified_parts:
            msg += (
                f" Additionally, {len(unverified_parts)} item(s) could not "
                f"be verified: {'; '.join(unverified_parts)}."
            )
        return msg

    @staticmethod
    def _format_manual(
        catalog_name: str,
        unverified_parts: List[str],
    ) -> str:
        """Format the MANUAL status_extended message.

        Args:
            catalog_name: Display name of the catalog.
            unverified_parts: List of unverified reference descriptions.

        Returns:
            A human-readable manual-review message.
        """
        parts_str = "; ".join(unverified_parts)
        return (
            f"Access package catalog {catalog_name} could not be fully "
            f"evaluated: {parts_str}."
        )


def _validate_app_role(
    rrs,
    pkg_display_name: str,
    app_roles: list,
    stale_items: List[str],
) -> None:
    """Check whether a role-scope's app role still exists and is enabled.

    Skips the default app role (all-zero GUID or ``Default Access``
    display name) and group membership roles (``Member_*`` / ``Owner_*``).

    Args:
        rrs: The AccessPackageResourceRoleScope to validate.
        pkg_display_name: Display name of the parent access package.
        app_roles: The service principal's appRoles list.
        stale_items: Mutable list to append stale descriptions to.
    """
    role_id = rrs.role_origin_id

    # Skip default app role
    if role_id == _DEFAULT_ROLE_ID:
        return
    if rrs.role_display_name == _DEFAULT_ROLE_DISPLAY_NAME:
        return

    # Skip group membership roles (Member_<groupId>, Owner_<groupId>)
    if role_id.startswith("Member_") or role_id.startswith("Owner_"):
        return

    # Look up the role in the SP's appRoles
    found = False
    enabled = False
    for app_role in app_roles:
        if app_role.get("id") == role_id:
            found = True
            enabled = app_role.get("isEnabled", False)
            break

    if not found:
        stale_items.append(
            f"removed app role '{rrs.role_display_name}' ({role_id}) "
            f"in access package '{pkg_display_name}'"
        )
    elif not enabled:
        stale_items.append(
            f"disabled app role '{rrs.role_display_name}' ({role_id}) "
            f"in access package '{pkg_display_name}'"
        )
