from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_authentication_method_no_deleted_group_references(Check):
    """Ensure authentication method configurations do not reference deleted groups.

    Every group referenced in the includeTargets or excludeTargets of each
    authentication method configuration in the tenant's authentication methods
    policy must still exist in Microsoft Entra ID. Deleted group references
    silently change the effective scope of authentication methods: an include
    target that no longer resolves means users lose access to a method, while a
    deleted exclude target means users who should be excluded are no longer
    excluded.

    The group existence check runs once at service init time and is cached on
    the entra client. This check reads from that cache and reports any
    configuration whose targets name a group id that no longer resolves.

    Disabled methods are included because their targets become effective as
    soon as they are enabled.

    - PASS: The configuration references no deleted groups (or only all_users).
    - FAIL: At least one referenced group id is confirmed deleted (HTTP 404).
    - MANUAL: At least one referenced group lookup failed with a non-404 error,
      or the targets could not be read, or the policy itself could not be read.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the authentication method deleted group references check.

        Returns:
            A list of reports, one per authentication method configuration.
        """
        findings = []

        configs = entra_client.authentication_method_configurations
        unresolved = entra_client.unresolved_authentication_method_group_references
        errored = entra_client.errored_authentication_method_group_references

        # If the authentication methods policy could not be read, emit a
        # single tenant-level MANUAL finding rather than returning nothing.
        if not configs and entra_client.authentication_method_configurations_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Authentication Methods Policy",
                resource_id="authenticationMethodsPolicy",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Authentication methods policy could not be read. "
                "Verify that Policy.Read.All permission is granted to the "
                "scanning application."
            )
            findings.append(report)
            return findings

        for method_id, config in configs.items():
            # Only configurations that reference groups are evaluated.
            if (
                config.targets_read
                and not config.include_target_group_ids
                and not config.exclude_target_group_ids
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=config,
                resource_name=method_id,
                resource_id=method_id,
            )

            # If targets could not be read for this configuration, MANUAL.
            if not config.targets_read:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Authentication method {method_id} ({config.state}) "
                    f"targets could not be read and cannot be evaluated."
                )
                findings.append(report)
                continue

            # Collect deleted and errored group ids for this configuration.
            deleted_include = [
                gid for gid in config.include_target_group_ids if gid in unresolved
            ]
            deleted_exclude = [
                gid for gid in config.exclude_target_group_ids if gid in unresolved
            ]
            errored_include = [
                gid for gid in config.include_target_group_ids if gid in errored
            ]
            errored_exclude = [
                gid for gid in config.exclude_target_group_ids if gid in errored
            ]

            has_deleted = bool(deleted_include or deleted_exclude)
            has_errored = bool(errored_include or errored_exclude)

            if has_deleted:
                report.status = "FAIL"
                report.status_extended = self._format_failure(
                    method_id,
                    config.state,
                    deleted_include,
                    deleted_exclude,
                    errored_include,
                    errored_exclude,
                )
            elif has_errored:
                report.status = "MANUAL"
                report.status_extended = self._format_manual(
                    method_id,
                    config.state,
                    errored_include,
                    errored_exclude,
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Authentication method {method_id} does not reference "
                    f"deleted groups."
                )

            findings.append(report)

        return findings

    @staticmethod
    def _format_deleted_list(include_ids: list[str], exclude_ids: list[str]) -> str:
        """Format deleted group ids into a human-readable string.

        Args:
            include_ids: List of deleted group ids from includeTargets.
            exclude_ids: List of deleted group ids from excludeTargets.

        Returns:
            A formatted string listing deleted group ids by target side.
        """
        parts = []
        for gid in sorted(include_ids):
            parts.append(f"include {gid}")
        for gid in sorted(exclude_ids):
            parts.append(f"exclude {gid}")
        return "; ".join(parts)

    @classmethod
    def _format_failure(
        cls,
        method_id: str,
        state: str,
        deleted_include: list[str],
        deleted_exclude: list[str],
        errored_include: list[str],
        errored_exclude: list[str],
    ) -> str:
        """Build the FAIL status_extended message.

        Args:
            method_id: The authentication method identifier.
            state: The method state (enabled/disabled).
            deleted_include: Deleted group ids from includeTargets.
            deleted_exclude: Deleted group ids from excludeTargets.
            errored_include: Errored group ids from includeTargets.
            errored_exclude: Errored group ids from excludeTargets.

        Returns:
            A descriptive failure message.
        """
        deleted_str = cls._format_deleted_list(deleted_include, deleted_exclude)

        unverified_note = ""
        total_errored = len(errored_include) + len(errored_exclude)
        if total_errored:
            unverified_note = (
                f" Additionally, {total_errored} reference(s) could not be "
                f"verified due to transient Microsoft Graph errors."
            )

        return (
            f"Authentication method {method_id} ({state}) references deleted "
            f"group(s): {deleted_str}.{unverified_note}"
        )

    @staticmethod
    def _format_manual(
        method_id: str,
        state: str,
        errored_include: list[str],
        errored_exclude: list[str],
    ) -> str:
        """Build the MANUAL status_extended message.

        Args:
            method_id: The authentication method identifier.
            state: The method state (enabled/disabled).
            errored_include: Errored group ids from includeTargets.
            errored_exclude: Errored group ids from excludeTargets.

        Returns:
            A descriptive manual-review message.
        """
        total_errored = len(errored_include) + len(errored_exclude)
        return (
            f"Authentication method {method_id} ({state}) could not be fully "
            f"evaluated: {total_errored} group reference(s) could not be "
            f"resolved due to transient Microsoft Graph errors. Re-run the "
            f"scan or review the configuration manually."
        )
