from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


class sqs_queues_server_side_encryption_enabled(Check):
    def execute(self):
        findings = []
        for queue in sqs_client.queues:
            report = Check_Report_AWS(self.metadata())
            report.region = queue.region
            report.resource_id = queue.id
            report.resource_arn = queue.arn
            report.status = "PASS"
            report.status_extended = (
                f"SQS queue {queue.id} is using Server Side Encryption"
            )
            if not queue.kms_key_id:
                report.status = "FAIL"
                report.status_extended = (
                    f"SQS queue {queue.id} is not using Server Side Encryption"
                )
            findings.append(report)

        return findings
