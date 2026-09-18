from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sqs.sqs_client import sqs_client

SQS_ACTIONS = {
    "sqs:addpermission",
    "sqs:cancelmessagemovetask",
    "sqs:changemessagevisibility",
    "sqs:changemessagevisibilitybatch",
    "sqs:createqueue",
    "sqs:deletemessage",
    "sqs:deletemessagebatch",
    "sqs:deletequeue",
    "sqs:getqueueattributes",
    "sqs:getqueueurl",
    "sqs:listdeadlettersourcequeues",
    "sqs:listmessagemovetasks",
    "sqs:listqueues",
    "sqs:listqueuetags",
    "sqs:purgequeue",
    "sqs:receivemessage",
    "sqs:removepermission",
    "sqs:sendmessage",
    "sqs:sendmessagebatch",
    "sqs:setqueueattributes",
    "sqs:startmessagemovetask",
    "sqs:tagqueue",
    "sqs:untagqueue",
}


class sqs_queues_secure_transport_enabled(Check):
    """Check that SQS queue policies deny insecure transport."""

    def execute(self) -> list[Check_Report_AWS]:
        """Evaluate secure transport enforcement for each SQS queue.

        Returns:
            One report for each SQS queue.
        """
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
                statements = queue.policy.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for statement in statements:
                    if "Action" not in statement:
                        continue
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        actions = [actions]
                    if not isinstance(actions, list) or not all(
                        isinstance(action, str) for action in actions
                    ):
                        continue
                    actions = {action.casefold() for action in actions}
                    if (
                        statement["Effect"] == "Deny"
                        and "Principal" in statement
                        and (
                            statement["Principal"] == "*"
                            or statement["Principal"] == {"AWS": "*"}
                        )
                        and "Condition" in statement
                        and (
                            "*" in actions
                            or "sqs:*" in actions
                            or SQS_ACTIONS <= actions
                        )
                    ):
                        if "Bool" in statement["Condition"]:
                            bool_conditions = statement["Condition"]["Bool"]
                            if isinstance(bool_conditions, dict):
                                normalized_bool_conditions = {
                                    str(key).casefold(): value
                                    for key, value in bool_conditions.items()
                                }
                                if (
                                    normalized_bool_conditions.get(
                                        "aws:securetransport"
                                    )
                                    == "false"
                                ):
                                    report.status = "PASS"
                                    report.status_extended = f"SQS queue {queue.id} has a policy to deny requests over insecure transport."

            findings.append(report)
        return findings
