from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.elb.elb_client import elb_client


class ec2_instance_not_directly_publicly_accessible_via_elb(Check):
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
                report.status_extended = f"EC2 Instance {instance.id} is not publicly accesible through an Internet facing Classic Load Balancer."

                for lb in elb_client.loadbalancers:
                    if lb.public and instance.id in lb.instances_ids:
                        # Check every listener of the Load Balancer
                        for listener in lb.listeners:
                            safe_sgs = []
                            for sg in ec2_client.security_groups:
                                if sg.id in lb.security_groups:
                                    listen_port = listener.port
                                elif sg.id in instance.security_groups:
                                    listen_port = listener.instance_port
                                else:
                                    listen_port = None

                                if listen_port:
                                    for rule in sg.ingress_rules:
                                        if check_security_group(
                                            ingress_rule=rule,
                                            protocol=rule.get("IpProtocol", ""),
                                            ports=[listen_port],
                                            any_address=True,
                                        ):
                                            safe_sgs.append(False)
                                            break
                                    else:
                                        safe_sgs.append(True)

                            if safe_sgs and not any(safe_sgs):
                                report.status = "FAIL"
                                report.status_extended = f"EC2 Instance {instance.id} is publicly accesible through an Internet facing Classic Load Balancer."
                                break

                findings.append(report)

        return findings
