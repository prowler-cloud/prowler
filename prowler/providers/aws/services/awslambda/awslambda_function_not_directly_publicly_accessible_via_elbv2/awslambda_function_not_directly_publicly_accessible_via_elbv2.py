from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class awslambda_function_not_directly_publicly_accessible_via_elbv2(Check):
    def execute(self):
        findings = []

        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags
            report.status = "PASS"
            report.status_extended = f"Lambda function '{function.name}' is not publicly accesible through an Internet facing Load Balancer."

            for target_group in elbv2_client.target_groups:
                # Lambda targets group len must be 1 by definition
                if (
                    target_group.target_type == "lambda"
                    and target_group.targets[0] == function.arn
                ):
                    for lb in elbv2_client.loadbalancersv2:
                        if lb.arn == target_group.load_balancer_arn and lb.public:
                            # Find for the lambda listener port and protocol
                            listen_port = None
                            listen_protocol = None
                            for listener in lb.listeners:
                                for rule in listener.rules:
                                    for action in getattr(rule, "actions", []):
                                        if (
                                            action.get("Type", "") == "forward"
                                            and action.get("TargetGroupArn", "")
                                            == target_group.arn
                                        ):
                                            listen_port = listener.port
                                            listen_protocol = (
                                                "tcp"
                                                if listener.protocol.upper() == "HTTP"
                                                else listener.protocol
                                            )
                                            break

                            # Check lb security groups
                            if listen_port and listen_protocol:
                                for lb_sg in lb.security_groups:
                                    for sg in ec2_client.security_groups:
                                        if lb_sg == sg.id:
                                            for rule in sg.ingress_rules:
                                                # Check if some listener is open in the range of the lambda function
                                                if check_security_group(
                                                    rule,
                                                    listen_protocol,
                                                    [listen_port],
                                                    True,
                                                ):
                                                    report.status = "FAIL"
                                                    report.status_extended = f"Lambda function '{function.name}' is publicly accesible through an Internet facing Load Balancer {lb.dns}."
                                                    break

            findings.append(report)

        return findings
