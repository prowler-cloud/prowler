from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class ec2_instance_not_directly_publicly_accessible_via_elbv2(Check):
    def execute(self):
        findings = []
        
        public_instances = {}
        for tg in elbv2_client.target_groups:
            if tg.public and tg.target_type == "instance":
                public_instances[tg.target] = tg.loadbalancer
        
        for instance in ec2_client.instances:
            if instance.state != "terminated":
                report = Check_Report_AWS(self.metadata())
                report.region = instance.region
                report.resource_id = instance.id
                report.resource_arn = instance.arn
                report.resource_tags = instance.tags
                report.status = "PASS"
                report.status_extended = f"EC2 Instance {instance.id} is not publicly accesible through an Internet facing Load Balancer."

                if instance.id in public_instances:
                    for sg in ec2_client.security_groups:
                        if sg.id in public_instances[instance.id].security_groups:
                            report.status = "FAIL"
                            report.status_extended = f"EC2 Instance {instance.id} is publicly accesible through an Internet facing Load Balancer through load balancer {public_instances[instance.id].dns}."
                            break     
                findings.append(report)
                    
        return findings
