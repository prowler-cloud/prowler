from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.organizations.organizations_client import (
    organizations_client,
)
from prowler.providers.aws.services.organizations.organizations_service import (
    ORGANIZATIONS_ACCESS_DENIED_ERROR_CODE,
)


class organizations_delegated_administrators(Check):
    """Check that every AWS Organizations delegated administrator is one you trust.

    A delegated administrator holds organization-wide authority over the service it was
    delegated, so an account registered as one that nobody intended is a standing path into
    every account in the organization. The trusted set comes from the
    `organizations_trusted_delegated_administrators` audit configuration, and an empty
    configuration is read as "none is trusted" rather than as "all are".

    Delegated administrators can only be listed from the management account or from a
    member account that is itself registered as a delegated administrator, so a scan run
    anywhere else cannot see them. That is reported as MANUAL rather than as a pass,
    because an unreadable inventory is not evidence of an empty one. Failures that are not
    an access denial name their own error code, so a retryable throttle is not answered
    with the advice to move accounts.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Compare every delegated administrator against the trusted list in the configuration.

        A single administrator outside the trusted list fails the organization, so the
        administrators are collected before the verdict is set rather than each one
        overwriting the verdict of the previous.

        Returns:
            A single report for the organization, or no report when the audited account
            is not part of an active organization. The report is MANUAL when the
            administrators could not be listed, and names the failure unless it was an
            access denial, which is reported as where the scan can run from and what the
            caller needs granted instead.
        """
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
            if organizations_client.organization.delegated_administrators is None:
                # The lookup failed, so there is nothing to compare against the trusted
                # list. Reporting that is a lack of visibility, not a misconfiguration.
                report.status = "MANUAL"
                # Only an access denial is answered by where the scan runs from and what
                # the caller is granted, and it can be either of those rather than only
                # the account. A throttle, a validation error or a transport failure leave
                # the same sentinel, so naming their code keeps them from being read as a
                # denial and from being sent the remediation for one.
                if (
                    organizations_client.organization.delegated_administrators_error_code
                    == ORGANIZATIONS_ACCESS_DENIED_ERROR_CODE
                ):
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} delegated administrators could not be determined; run this check from the organization management account or a registered delegated administrator, with organizations:ListDelegatedAdministrators allowed for the caller."
                else:
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} delegated administrators could not be determined: {organizations_client.organization.delegated_administrators_error_code}."
                findings.append(report)
            else:
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

                    # Reported in a sorted order rather than in the order the response
                    # happened to arrive in, so that one set of administrators does not
                    # read as two different findings across scans.
                    untrusted.sort()
                    trusted.sort()

                    if untrusted:
                        report.status = "FAIL"
                        subject = (
                            "an untrusted Delegated Administrator"
                            if len(untrusted) == 1
                            else "untrusted Delegated Administrators"
                        )
                        report.status_extended = f"AWS Organization {organizations_client.organization.id} has {subject}: {', '.join(untrusted)}."
                    else:
                        report.status = "PASS"
                        subject = (
                            "a trusted Delegated Administrator"
                            if len(trusted) == 1
                            else "trusted Delegated Administrators"
                        )
                        report.status_extended = f"AWS Organization {organizations_client.organization.id} has {subject}: {', '.join(trusted)}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"AWS Organization {organizations_client.organization.id} has no Delegated Administrators."

                findings.append(report)

        return findings
