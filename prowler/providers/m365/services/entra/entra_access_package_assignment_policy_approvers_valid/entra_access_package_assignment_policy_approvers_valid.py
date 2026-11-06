from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import ApproverStatus

# Approver OData types that cannot be validated statically.
_UNVERIFIABLE_TYPES = {
    "#microsoft.graph.requestorManager",
    "#microsoft.graph.internalSponsors",
    "#microsoft.graph.externalSponsors",
    "#microsoft.graph.targetUserSponsors",
}

# Human-readable labels for approver status codes.
_STATUS_LABELS = {
    ApproverStatus.USER_DELETED: "approver user deleted",
    ApproverStatus.USER_DISABLED: "approver user disabled",
    ApproverStatus.GROUP_DELETED: "approver group deleted",
    ApproverStatus.GROUP_EMPTY: "approver group empty",
    ApproverStatus.INVALID_ENTRY: "invalid approver entry",
    ApproverStatus.ERROR: "could not verify approver",
}


class entra_access_package_assignment_policy_approvers_valid(Check):
    """Ensure access package approval workflows have valid primary approvers.

    Every access package assignment policy that requires approval must have at
    least one approval stage, every stage must have at least one primary
    approver, and every singleUser or groupMembers approver must resolve to an
    active, non-empty principal. Manager and sponsor approver types cannot be
    validated statically and are accepted as-is.

    - PASS: All stages have valid primary approvers.
    - FAIL: At least one stage has missing, deleted, disabled, or empty
      approvers.
    - MANUAL: Assignment policies could not be listed (tenant-level), or
      approver lookups failed with non-404 errors and nothing else was
      confirmed invalid (policy-level).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings: List[CheckReportM365] = []

        # Tenant-level error: could not list assignment policies at all.
        if entra_client.assignment_policies is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Entitlement management",
                resource_id="entitlementManagement",
            )
            report.status = "MANUAL"
            error_detail = entra_client.assignment_policies_error or "unknown error"
            report.status_extended = (
                "Cannot evaluate access package assignment policy approvers: "
                f"unable to list assignment policies ({error_detail}). "
                "Verify that the EntitlementManagement.Read.All permission is "
                "granted and that the tenant has a Microsoft Entra ID P2 or "
                "Entra ID Governance license."
            )
            findings.append(report)
            return findings

        # No policies requiring approval — no findings.
        for policy in entra_client.assignment_policies:
            resource_name = self._resource_name(policy)
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=resource_name,
                resource_id=policy.id,
            )

            problems = []
            unverified = []
            has_error = False

            # Check 1: no stages at all.
            if not policy.stages:
                problems.append("no approval stages configured")
            else:
                for stage_idx, stage in enumerate(policy.stages, start=1):
                    # Check 2: stage has no primary approvers.
                    if not stage.primary_approvers:
                        problems.append(f"stage {stage_idx} has no primary approvers")
                        continue

                    for approver in stage.primary_approvers:
                        if approver.odata_type in _UNVERIFIABLE_TYPES:
                            unverified.append(
                                f"stage {stage_idx}: "
                                f"{approver.odata_type.rsplit('.', 1)[-1]} "
                                f"(not validated statically)"
                            )
                            continue

                        if approver.resolution is None:
                            # Should not happen, but treat as unverified.
                            unverified.append(
                                f"stage {stage_idx}: approver not resolved"
                            )
                            has_error = True
                            continue

                        status = approver.resolution.status
                        if status == ApproverStatus.VALID:
                            continue
                        elif status == ApproverStatus.ERROR:
                            has_error = True
                            identifier = (
                                approver.user_id or approver.group_id or "unknown"
                            )
                            unverified.append(
                                f"stage {stage_idx}: "
                                f"{approver.odata_type.rsplit('.', 1)[-1]} "
                                f"{identifier} (lookup failed)"
                            )
                        else:
                            # Confirmed invalid.
                            label = _STATUS_LABELS.get(status, str(status))
                            identifier = (
                                approver.user_id or approver.group_id or "unknown"
                            )
                            name_part = ""
                            if approver.resolution.display_name:
                                name_part = f" '{approver.resolution.display_name}'"
                            problems.append(
                                f"stage {stage_idx}: {label} — "
                                f"{identifier}{name_part}"
                            )

            if problems:
                report.status = "FAIL"
                detail = "; ".join(problems)
                unverified_note = ""
                if unverified:
                    unverified_note = (
                        f" Additionally, {len(unverified)} approver(s) "
                        f"could not be verified: {'; '.join(unverified)}."
                    )
                report.status_extended = (
                    f"Access package assignment policy {resource_name} has "
                    f"invalid approvers: {detail}.{unverified_note}"
                )
            elif has_error:
                report.status = "MANUAL"
                detail = "; ".join(unverified)
                report.status_extended = (
                    f"Access package assignment policy {resource_name} could "
                    f"not be fully evaluated: {detail}. Re-run the scan or "
                    f"verify approvers manually."
                )
            else:
                report.status = "PASS"
                unverified_note = ""
                if unverified:
                    unverified_note = (
                        f" ({len(unverified)} manager/sponsor approver(s) "
                        f"accepted without static validation)"
                    )
                report.status_extended = (
                    f"Access package assignment policy {resource_name} has "
                    f"valid primary approvers in all stages.{unverified_note}"
                )

            findings.append(report)

        return findings

    @staticmethod
    def _resource_name(policy) -> str:
        """Build the resource name from the access package and policy names.

        Args:
            policy: The access package assignment policy.

        Returns:
            str: A display string in the format
                ``<access_package_name> / <policy_name>``.
        """
        ap_name = policy.access_package_name or "Unknown access package"
        return f"{ap_name} / {policy.display_name}"
