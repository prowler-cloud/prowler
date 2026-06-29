"""Check storage service-level administrators cannot delete managed resources."""

import re

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)

STORAGE_DELETE_PERMISSIONS_BY_RESOURCE = {
    "volumes": {"VOLUME_DELETE"},
    "volume-backups": {"VOLUME_BACKUP_DELETE"},
    "file-systems": {"FILE_SYSTEM_DELETE"},
    "mount-targets": {"MOUNT_TARGET_DELETE"},
    "export-sets": {"EXPORT_SET_DELETE"},
    "objects": {"OBJECT_DELETE"},
    "buckets": {"BUCKET_DELETE"},
    "volume-family": {"VOLUME_DELETE", "VOLUME_BACKUP_DELETE"},
    "file-family": {"FILE_SYSTEM_DELETE", "MOUNT_TARGET_DELETE", "EXPORT_SET_DELETE"},
    "object-family": {"OBJECT_DELETE", "BUCKET_DELETE"},
}
ALL_STORAGE_DELETE_PERMISSIONS = set().union(
    *STORAGE_DELETE_PERMISSIONS_BY_RESOURCE.values()
)
STORAGE_DELETE_PERMISSIONS_BY_RESOURCE["all-resources"] = ALL_STORAGE_DELETE_PERMISSIONS

MANAGE_STATEMENT_PATTERN = re.compile(
    r"\ballow\s+group\b.+?\bto\s+manage\s+(?P<resource>[a-z-]+)\b",
    re.IGNORECASE,
)
QUOTED_LITERAL_PATTERN = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")


def _normalize_statement(statement: str) -> str:
    """Collapse whitespace in an OCI policy statement."""
    return " ".join(statement.strip().split())


def _has_disjunctive_condition(statement: str) -> bool:
    """Return True when the WHERE condition can allow alternate branches."""
    condition = re.split(r"\bwhere\b", statement, flags=re.IGNORECASE, maxsplit=1)
    if len(condition) != 2:
        return False

    condition_without_literals = QUOTED_LITERAL_PATTERN.sub("", condition[1])
    return bool(
        re.search(r"\b(any|or)\b|\|\|", condition_without_literals, re.IGNORECASE)
    )


def _storage_manage_resource(statement: str) -> str | None:
    """Return the managed storage resource in a policy statement, if any."""
    normalized_statement = _normalize_statement(statement)
    match = MANAGE_STATEMENT_PATTERN.search(normalized_statement)
    if not match:
        return None

    resource = match.group("resource").lower()
    if resource not in STORAGE_DELETE_PERMISSIONS_BY_RESOURCE:
        return None

    return resource


def _excluded_permissions(statement: str) -> set[str]:
    """Return delete permissions explicitly excluded with request.permission != value."""
    if _has_disjunctive_condition(statement):
        return set()

    exclusions = set()
    for permission in ALL_STORAGE_DELETE_PERMISSIONS:
        pattern = re.compile(
            rf"\brequest\.permission\s*!=\s*['\"]?{re.escape(permission)}['\"]?\b",
            re.IGNORECASE,
        )
        if pattern.search(statement):
            exclusions.add(permission)
    return exclusions


def _missing_delete_exclusions(statement: str) -> tuple[str, set[str]] | None:
    """Return the storage resource and missing delete exclusions for a statement."""
    normalized_statement = _normalize_statement(statement)
    resource = _storage_manage_resource(normalized_statement)
    if not resource:
        return None

    required_permissions = STORAGE_DELETE_PERMISSIONS_BY_RESOURCE[resource]

    excluded_permissions = _excluded_permissions(normalized_statement)
    missing_permissions = required_permissions - excluded_permissions
    if not missing_permissions:
        return None

    return resource, missing_permissions


class identity_storage_service_level_admins_scoped(Check):
    """Ensure storage service-level admins cannot delete resources they manage."""

    def execute(self) -> list[Check_Report_OCI]:
        """Execute the storage service-level administrators scoped check.

        Returns:
            A list of OCI check reports for active non-tenant-admin policies.
        """
        findings = []

        for policy in identity_client.policies:
            if policy.lifecycle_state != "ACTIVE":
                continue

            if policy.name.upper() == "TENANT ADMIN POLICY":
                continue

            region = policy.region if hasattr(policy, "region") else "global"
            violations = []
            has_storage_manage_statement = False

            for statement in policy.statements:
                if _storage_manage_resource(statement):
                    has_storage_manage_statement = True

                missing_result = _missing_delete_exclusions(statement)
                if not missing_result:
                    continue

                resource, missing_permissions = missing_result
                violations.append(
                    f"statement `{_normalize_statement(statement)}` manages {resource} without excluding: {', '.join(sorted(missing_permissions))}"
                )

            if not has_storage_manage_statement:
                continue

            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=policy,
                region=region,
                resource_id=policy.id,
                resource_name=policy.name,
                compartment_id=policy.compartment_id,
            )

            if violations:
                report.status = "FAIL"
                report.status_extended = (
                    f"Policy '{policy.name}' allows storage service-level administrators to manage storage resources without explicitly excluding required delete permissions: "
                    + "; ".join(violations)
                    + "."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Policy '{policy.name}' excludes required storage delete permissions from storage manage statements."

            findings.append(report)

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
            report.status_extended = "No active storage service-level administrator policies grant manage permissions without excluding delete permissions."
            findings.append(report)

        return findings
