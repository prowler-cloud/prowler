from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class ec2_instance_not_directly_publicly_accessible_via_elbv2(Check):
    def execute(self):
        findings = []

        for instance in ec2_client.instances:
            if instance.state != "terminated":
                report = Check_Report_AWS(self.metadata())
                report.region = instance.region
                report.resource_id = instance.id
                report.resource_arn = instance.arn
                report.resource_tags = instance.tags
                report.status = "PASS"
                report.status_extended = f"EC2 Instance {instance.id} is not publicly accesible through an Internet facing Load Balancer."

                for target_group in elbv2_client.target_groups:
                    if target_group.target_type == "instance" and any(
                        target == instance.id for target in target_group.targets
                    ):
                        for lb in elbv2_client.loadbalancersv2:
                            if lb.arn == target_group.load_balancer_arn and lb.public:
                                # Find for the ec2 listener port
                                listen_port = None
                                for listener in lb.listeners:
                                    for rule in listener.rules:
                                        for action in getattr(rule, "actions", []):
                                            if action.get("Type", "") == "forward" and (
                                                any(
                                                    tg.get("TargetGroupArn", "")
                                                    == target_group.arn
                                                    for tg in action["ForwardConfig"][
                                                        "TargetGroups"
                                                    ]
                                                )
                                                if "TargetGroups"
                                                in action.get("ForwardConfig", {})
                                                else action.get("TargetGroupArn", "")
                                                == target_group.arn
                                            ):
                                                listen_port = listener.port
                                                break

                                # Check lb and ec2 security groups
                                if listen_port:
                                    safe_sgs = []
                                    for sg in ec2_client.security_groups:
                                        if any(
                                            sg.id == lb_sg
                                            for lb_sg in lb.security_groups
                                        ) or any(
                                            sg.id == instance_sg
                                            for instance_sg in instance.security_groups
                                        ):
                                            for rule in sg.ingress_rules:
                                                if check_security_group(
                                                    ingress_rule=rule,
                                                    protocol=rule.get(
                                                        "IpProtocol", "tcp"
                                                    ),
                                                    ports=[listen_port],
                                                    any_address=True,
                                                ):
                                                    safe_sgs.append(False)
                                                    break
                                                safe_sgs.append(True)
                                    # If there is not any security group safe, the instance is publicly accessible
                                    if not any(safe_sgs):
                                        report.status = "FAIL"
                                        report.status_extended = f"EC2 Instance {instance.id} is publicly accesible through an Internet facing Load Balancer '{lb.dns}'."
                                        break

                findings.append(report)

        return findings
