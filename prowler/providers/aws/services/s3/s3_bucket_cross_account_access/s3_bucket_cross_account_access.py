from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client
from prowler.providers.aws.services.s3.s3_service import BlacklistedActions


class s3_bucket_cross_account_access(Check):
    def execute(self):
        findings = []
        for arn, bucket in s3_client.buckets.items():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = arn
            report.resource_tags = bucket.tags
            allowed_actions = []
            report.status = "PASS"
            report.status_extended = f"S3 Bucket {bucket.name} does not allow actions to be performed by principals from other AWS accounts."

            if not bucket.policy:
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have any policy attached."
                )
            else:
                for statement in bucket.policy.get("Statement", []):
                    if statement.get("Effect") == "Allow":
                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        principals = statement.get("Principal", {})

                        if (
                            isinstance(principals, dict)
                            and principals.get("AWS") != s3_client.audited_account_arn
                        ):
                            for action in actions:
                                if action in [bla.value for bla in BlacklistedActions]:
                                    report.status = "FAIL"
                                    allowed_actions.append(action)

                if report.status == "FAIL":
                    report.status_extended = f"S3 Bucket {bucket.name} does allow actions {', '.join(allowed_actions)} to be performed by principals from other AWS accounts."

            findings.append(report)

        return findings
