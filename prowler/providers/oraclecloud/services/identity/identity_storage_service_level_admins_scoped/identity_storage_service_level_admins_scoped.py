from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)

class identity_storage_service_level_admins_scoped(Check):
    """Ensure storage service-level admins cannot delete resources they manage (CIS 1.15)"""

    def execute(self):
        """Ensure service-level administrators can only manage resources of a specific service but not delete resources.

        This check ensures that policies don't grant delete permission on storage like "manage volumes in tenancy"
        without restricting delete permissions.
        """
        findings = []

        storage_policies = {
            "FILE-FAMILY": [
                "FILE-SYSTEMS",
                "MOUNT-TARGETS",
                "EXPORT-SETS"
            ],
            "OBJECT-FAMILY": [
                "BUCKETS",
                "OBJECTS"
            ],
            "VOLUME-FAMILY": [
                "VOLUMES",
                "VOLUME-ATTACHMENTS",
                "VOLUME-BACKUPS"
            ]
        }
        all_base_policies = [item for sublist in storage_policies.values() for item in sublist]

        # Check for policies that violate least privilege by granting manage all-resources
        for policy in identity_client.policies:
            # Skip non-active policies
            if policy.lifecycle_state != "ACTIVE":
                continue

            # Skip default tenant admin policy
            if policy.name.upper() == "TENANT ADMIN POLICY":
                continue

            region = policy.region if hasattr(policy, "region") else "global"

            has_violation = False
            offending_statement = None
            for statement in policy.statements:
                statement_upper = statement.upper()
                # Only check groups
                if not statement_upper.startswith("ALLOW GROUP"):
                    continue

                # Check for "allow group ... to manage file service resources without restriction" (not specific to service/compartment)
                if any(f"MANAGE {global_storage_policy}" in statement_upper for global_storage_policy in storage_policies):
                    if "WHERE" not in statement_upper:
                        has_violation = True
                        offending_statement = statement
                        break
                if any(f"MANAGE {base_storage_policy}" in statement_upper for base_storage_policy in all_base_policies):
                    if "WHERE" not in statement_upper:
                        has_violation = True
                        offending_statement = statement
                        break
                if "MANAGE ALL-RESOURCES" in statement_upper:
                    if "WHERE" not in statement_upper:
                        has_violation = True
                        offending_statement = statement
                        break
                
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=policy,
                region=region,
                resource_id=policy.id,
                resource_name=policy.name,
                compartment_id=policy.compartment_id,
            )

            if has_violation:
                report.status = "FAIL"
                report.status_extended = f"Policy '{policy.name}' grants 'manage' permissions with delete. Service-level storage administrators should be created with delete permissions.\n{offending_statement}"
            else:
                report.status = "PASS"
                report.status_extended = f"Policy '{policy.name}' does not grant storage service level admins delete permissions."

            findings.append(report)

        # If no policies found, that's also a finding
        if not findings:
            region = (
                identity_client.audited_regions[0].key
                if identity_client.audited_regions
                else "global"
            )
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region=region,
                resource_id=identity_client.audited_tenancy,
                resource_name="Tenancy",
                compartment_id=identity_client.audited_tenancy,
            )
            report.status = "PASS"
            report.status_extended = (
                "No active storage-level admin policies found with delete permissions."
            )
            findings.append(report)

        return findings