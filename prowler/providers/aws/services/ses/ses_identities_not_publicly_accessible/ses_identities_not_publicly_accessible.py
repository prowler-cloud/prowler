from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.ses.ses_client import ses_client


class ses_identities_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for identity in ses_client.email_identities.values():
            report = Check_Report_AWS(self.metadata())
            report.region = identity.region
            report.resource_id = identity.name
            report.resource_arn = identity.arn
            report.resource_tags = identity.tags
            report.status = "PASS"
            report.status_extended = (
                f"SES identity {identity.name} does not have a public policy."
            )
            if is_policy_public(identity.policy, ses_client.audited_account):
                report.status = "FAIL"
                report.status_extended = (
                    f"SES identity {identity.name} has a public policy."
                )

            findings.append(report)

        return findings
