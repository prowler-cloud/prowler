"""Check that entitlement management catalogs contain no unused resources."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_access_package_catalog_no_unused_resources(Check):
    """Entitlement management catalog has no resources without an associated access package.

    Every resource (group, application) added to an entitlement management
    catalog should be referenced by at least one access package of that
    catalog via a resourceRoleScope. Resources that sit in a catalog without
    being packaged represent delegated access surface with no business purpose.

    - PASS: The catalog has no resources, or every resource's originId is
      referenced by at least one resourceRoleScope of an access package in the
      same catalog.
    - FAIL: At least one catalog resource is not referenced by any access
      package of the catalog.
    - MANUAL: Catalogs, resources, access packages, or resourceRoleScopes
      could not be read (missing permissions, licensing, or API errors).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the unused catalog resources check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # Tenant-level MANUAL if catalogs could not be listed at all.
        if entra_client.access_package_catalogs is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Entitlement management",
                resource_id="entitlementManagement",
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate entitlement management catalogs: "
                f"{entra_client.entitlement_management_error or 'unknown error'}."
            )
            findings.append(report)
            return findings

        for catalog in entra_client.access_package_catalogs:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=catalog,
                resource_name=catalog.display_name,
                resource_id=catalog.id,
            )

            # If resources could not be read, report MANUAL.
            if catalog.resources_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Entitlement management catalog '{catalog.display_name}' "
                    f"(catalogType={catalog.catalog_type}) could not be evaluated: "
                    f"{catalog.resources_error}."
                )
                findings.append(report)
                continue

            # No resources in catalog -> PASS (nothing is delegated).
            if not catalog.resources:
                report.status = "PASS"
                report.status_extended = (
                    f"Entitlement management catalog '{catalog.display_name}' "
                    f"(catalogType={catalog.catalog_type}) has no resources."
                )
                findings.append(report)
                continue

            # Collect access packages that belong to this catalog.
            if catalog.access_packages_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Entitlement management catalog '{catalog.display_name}' "
                    f"(catalogType={catalog.catalog_type}) could not be evaluated: "
                    f"{catalog.access_packages_error}."
                )
                findings.append(report)
                continue

            catalog_packages = catalog.access_packages or []

            # Check if any access package's resourceRoleScopes failed to read.
            failed_packages = [
                ap
                for ap in catalog_packages
                if ap.resource_role_scopes_error is not None
            ]
            if failed_packages:
                failed_names = ", ".join(
                    f"'{ap.display_name}' ({ap.id})" for ap in failed_packages
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"Entitlement management catalog '{catalog.display_name}' "
                    f"(catalogType={catalog.catalog_type}) could not be fully "
                    f"evaluated because resourceRoleScopes could not be read for "
                    f"access package(s): {failed_names}."
                )
                findings.append(report)
                continue

            # Build set of used originIds (case-insensitive).
            used_origin_ids = set()
            for ap in catalog_packages:
                for rrs in ap.resource_role_scopes or []:
                    used_origin_ids.add(rrs.scope_origin_id.lower())

            # Determine unused resources.
            unused_resources = [
                res
                for res in catalog.resources
                if res.origin_id.lower() not in used_origin_ids
            ]

            num_packages = len(catalog_packages)
            if not unused_resources:
                report.status = "PASS"
                report.status_extended = (
                    f"Entitlement management catalog '{catalog.display_name}' "
                    f"(catalogType={catalog.catalog_type}) has "
                    f"{len(catalog.resources)} resource(s) all referenced by "
                    f"{num_packages} access package(s)."
                )
            else:
                unused_details = "; ".join(
                    f"'{res.display_name}' ({res.origin_system}, {res.origin_id})"
                    for res in unused_resources
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Entitlement management catalog '{catalog.display_name}' "
                    f"(catalogType={catalog.catalog_type}) has "
                    f"{len(unused_resources)} unused resource(s) not referenced "
                    f"by any of its {num_packages} access package(s): "
                    f"{unused_details}."
                )

            findings.append(report)

        return findings
