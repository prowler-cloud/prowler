from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)


class organizations_delegated_administrators(Check):
    def execute(self):
        findings = []

        # `or []` covers the key being present but null in the configuration file,
        # which `.get` returns as None and every membership test below then raises on.
        organizations_trusted_delegated_administrators = (
            organizations_client.audit_config.get(
                "organizations_trusted_delegated_administrators", []
            )
            or []
        )

        if (
            organizations_client.organization
            and organizations_client.organization.status == "ACTIVE"
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=organizations_client.organization,
            )
            report.region = organizations_client.region
            if (
                organizations_client.organization.delegated_administrators is not None
            ):  # Check if Access Denied to list_delegated_administrators
                if organizations_client.organization.delegated_administrators:
                    # Setting the verdict per administrator on a shared report let a
                    # trusted entry overwrite an untrusted one, and
                    # ListDelegatedAdministrators documents no ordering.
                    untrusted = []
                    trusted = []
                    for (
                        delegated_administrator
                    ) in organizations_client.organization.delegated_administrators:
                        if (
                            delegated_administrator.id
                            not in organizations_trusted_delegated_administrators
                        ):
                            untrusted.append(delegated_administrator.id)
                        else:
                            trusted.append(delegated_administrator.id)

                    if untrusted:
                        report.status = "FAIL"
                        report.status_extended = f"AWS Organization {organizations_client.organization.id} has an untrusted Delegated Administrator: {', '.join(untrusted)}."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"AWS Organization {organizations_client.organization.id} has a trusted Delegated Administrator: {', '.join(trusted)}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} has no Delegated Administrators."

                findings.append(report)

        return findings
