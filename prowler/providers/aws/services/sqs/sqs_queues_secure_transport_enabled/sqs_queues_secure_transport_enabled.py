from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


class sqs_queues_secure_transport_enabled(Check):
    def execute(self):
        findings = []
        for queue in sqs_client.queues:
            report = Check_Report_AWS(metadata=self.metadata(), resource=queue)
            # Check if SQS policy enforces SSL
            if not queue.policy:
                report.status = "FAIL"
                report.status_extended = f"SQS queue {queue.id} does not have a policy, thus it allows HTTP requests."
            else:
                report.status = "FAIL"
                report.status_extended = f"SQS queue {queue.id} allows requests over insecure transport in the policy."
                for statement in queue.policy["Statement"]:
                    if (
                        statement["Effect"] == "Deny"
                        and "Condition" in statement
                        and "Action" in statement
                        and (
                            "sqs:SendMessage" in statement["Action"]
                            or "*" in statement["Action"]
                            or "sqs:*" in statement["Action"]
                        )
                    ):
                        if "Bool" in statement["Condition"]:
                            if "aws:SecureTransport" in statement["Condition"]["Bool"]:
                                if (
                                    statement["Condition"]["Bool"][
                                        "aws:SecureTransport"
                                    ]
                                    == "false"
                                ):
                                    report.status = "PASS"
                                    report.status_extended = f"SQS queue {queue.id} has a policy to deny requests over insecure transport."

            findings.append(report)
        return findings
