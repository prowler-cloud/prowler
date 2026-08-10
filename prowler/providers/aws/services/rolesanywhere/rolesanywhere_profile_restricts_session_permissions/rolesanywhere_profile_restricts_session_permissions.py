from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rolesanywhere.rolesanywhere_client import (
    rolesanywhere_client,
)


class rolesanywhere_profile_restricts_session_permissions(Check):
    """Verify that IAM Roles Anywhere profiles scope down the vended session.

    A Roles Anywhere profile that defines neither an inline ``sessionPolicy`` nor
    ``managedPolicyArns`` vends temporary credentials carrying the full
    permissions of every role it references. Any certificate accepted by the
    associated trust anchor can then wield those permissions, turning the
    profile into a durable privileged-access path that surviving key rotation
    does not remove. Profiles that restrict the session are reported as PASS.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate session-permission scoping for Roles Anywhere profiles.

        Returns:
            list[Check_Report_AWS]: One report per Roles Anywhere profile. FAIL
            for enabled profiles that define neither a session policy nor managed
            policies; PASS for scoped or disabled profiles.
        """
        findings = []
        for profile in rolesanywhere_client.profiles.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=profile)
            scoped = bool(profile.session_policy) or bool(profile.managed_policy_arns)
            if not profile.enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} is disabled and "
                    "cannot vend session credentials."
                )
            elif scoped:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} restricts vended "
                    "session permissions with a session policy or managed policies."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Roles Anywhere profile {profile.name} does not scope down "
                    "sessions; certificates authenticated through it inherit the full "
                    f"permissions of its role(s) {', '.join(profile.role_arns) or '<none>'}, "
                    "enabling durable privileged access."
                )
            findings.append(report)

        return findings
