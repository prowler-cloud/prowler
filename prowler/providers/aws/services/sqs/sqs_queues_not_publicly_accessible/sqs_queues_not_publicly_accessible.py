from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_condition_block_restrictive
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


class sqs_queues_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for queue in sqs_client.queues:
            report = Check_Report_AWS(self.metadata())
            report.region = queue.region
            report.resource_id = queue.id
            report.resource_arn = queue.arn
            report.resource_tags = queue.tags
            report.status = "PASS"
            report.status_extended = f"SQS queue {queue.id} is not public."
            if queue.policy:
                for statement in queue.policy["Statement"]:
                    # Only check allow statements
                    if statement["Effect"] == "Allow":
                        if "Principal" in statement and (
                            "*" in statement["Principal"]
                            or (
                                "AWS" in statement["Principal"]
                                and "*" in statement["Principal"]["AWS"]
                            )
                            or (
                                "CanonicalUser" in statement["Principal"]
                                and "*" in statement["Principal"]["CanonicalUser"]
                            )
                        ):
                            if "Condition" in statement:
                                if is_condition_block_restrictive(
                                    statement["Condition"],
                                    sqs_client.audited_account,
                                    True,
                                ):
                                    report.status_extended = f"SQS queue {queue.id} is not public because its policy only allows access from the same account."
                                else:
                                    report.status = "FAIL"
                                    report.status_extended = f"SQS queue {queue.id} is public because its policy allows public access, and the condition does not limit access to resources within the same account."
                                    break
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SQS queue {queue.id} is public because its policy allows public access."
                                break
            findings.append(report)

        return findings
