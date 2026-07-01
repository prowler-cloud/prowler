from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_default_app_management_policy_enabled(Check):
    """
    Check if the default app management policy has the required credential restrictions configured.

    This check verifies that the tenant-wide default app management policy enforces
    the required credential restrictions on applications: block password addition,
    restrict max password lifetime, block custom passwords, and restrict max certificate lifetime.
    """

    REQUIRED_PASSWORD_RESTRICTIONS = {
        "passwordAddition": "Block password addition",
        "passwordLifetime": "Restrict max password lifetime",
        "customPasswordAddition": "Block custom passwords",
    }
    REQUIRED_KEY_RESTRICTIONS = {
        "asymmetricKeyLifetime": "Restrict max certificate lifetime",
    }

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the default app management policy check.

        Verifies that the required credential restrictions are configured
        and not disabled in the application restrictions of the policy.

        Returns:
            List[CheckReportM365]: A list containing the check report.
        """
        findings = []
        policy = entra_client.default_app_management_policy

        if policy:
            report = CheckReportM365(
                self.metadata(),
                resource=policy,
                resource_name="Default App Management Policy",
                resource_id=policy.id or entra_client.tenant_domain,
            )

            if not policy.is_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    "Default app management policy is not enabled, "
                    "credential restrictions are not enforced."
                )
            else:
                app_restrictions = policy.application_restrictions

                enabled_pwd_types = set()
                enabled_key_types = set()

                if app_restrictions:
                    for cred in app_restrictions.password_credentials:
                        if cred.state != "disabled":
                            enabled_pwd_types.add(cred.restriction_type)
                    for cred in app_restrictions.key_credentials:
                        if cred.state != "disabled":
                            enabled_key_types.add(cred.restriction_type)

                missing = []
                for rtype, name in self.REQUIRED_PASSWORD_RESTRICTIONS.items():
                    if rtype not in enabled_pwd_types:
                        missing.append(name)
                for rtype, name in self.REQUIRED_KEY_RESTRICTIONS.items():
                    if rtype not in enabled_key_types:
                        missing.append(name)

                if not missing:
                    report.status = "PASS"
                    report.status_extended = (
                        "Default app management policy has all required credential "
                        "restrictions configured: block password addition, restrict "
                        "max password lifetime, block custom passwords, and restrict "
                        "max certificate lifetime."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        "Default app management policy is missing the following "
                        f"credential restrictions: {', '.join(missing)}."
                    )

            findings.append(report)

        return findings
